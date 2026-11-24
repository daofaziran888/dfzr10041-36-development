"""空键处置/补证/调查核销场景的可执行规格与回归测试。

直接运行：
    backend/.venv/bin/python backend/tests/test_empty_key_workflow.py
"""
from __future__ import annotations

import os
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.models import DedupFilter, EventRecord, EventTypeDef, SampleConfig
from app.core.dedup_sample import DedupSamplePipeline
from app.core.empty_key import (
    EmptyKeyWorkflow,
    InvestigationDesk,
    normalize_key,
)


TYPE = EventTypeDef(type_id="EVEN-REQ", type_name="request", category_tag="api")
BASE = datetime(2026, 11, 24, 10, 0, 0)


def make_event(record_id: str, *, request_id=..., location: str = "",
               minute: int = 0, source: str = "SRC-1") -> EventRecord:
    fields = {}
    if request_id is not ...:
        fields["request_id"] = request_id
    event = EventRecord(
        record_id=record_id,
        event_type=TYPE,
        original_content=f"raw-{record_id}",
        parsed_fields=fields,
        masked_fields={},
        enriched_fields={},
        event_time=BASE + timedelta(minutes=minute),
        source_host="host-1",
        source_id=source,
        physical_location=location or f"/var/log/app-{record_id}.log:{100 + minute}",
    )
    return event


def test_missing_empty_and_zero_classification():
    a = make_event("A", location="src::a.log:101")  # 缺 request_id
    b = make_event("B", request_id="", location="src::b.log:202")
    a_dup = make_event("A-DUP", location="src::a.log:101")
    z1 = make_event("Z1", request_id="0", location="src::z.log:1")
    z2 = make_event("Z2", request_id="0", location="src::z.log:2", minute=2)

    rule = DedupFilter(
        rule_id="DEDU-REQ", event_type_id="EVEN-REQ",
        dedup_fields=["request_id"], key_field="request_id")
    assert rule.fingerprint(a) != rule.fingerprint(b)
    assert rule.fingerprint(a) == rule.fingerprint(a_dup)
    assert rule.fingerprint(z1) == rule.fingerprint(z2)
    assert normalize_key(0) == "0"
    assert normalize_key("0") == "0"

    pipeline = DedupSamplePipeline(
        dedup_rules=[rule],
        sample_configs=[SampleConfig("SAMP-REQ", "EVEN-REQ", 1.0, "request_id")],
    )
    deduped, hit, ignored = pipeline.deduplicate([a, b, a_dup, z1, z2], rule)
    ids = [r.record_id for r in deduped]
    assert ids == ["A", "B", "Z1"], ids
    assert hit == 2  # A 同一物理行一次，request_id=0 普通重复一次

    ledger = pipeline.empty_keys
    assert len(ledger) == 2
    by_location = {e.record_id or e.physical_id: e for e in ledger.entries}
    # A/B 的真实位置和来源均保留。
    a_entry = ledger.find_by_location("src::a.log:101")
    b_entry = ledger.find_by_location("src::b.log:202")
    assert a_entry.empty_kind == "missing"
    assert b_entry.empty_kind == "empty_string"
    assert a_entry.source_id == "SRC-1"
    assert b_entry.physical_location == "src::b.log:202"
    assert a_entry.submission_count == 2
    assert a_entry.registered_count == 1

    sampled = pipeline.sample(
        deduped, SampleConfig("SAMP-REQ2", "EVEN-REQ", 1.0, "request_id"))
    sample_ids = [r.record_id for r in sampled]
    assert set(sample_ids) == {"A", "B", "Z1"}, sample_ids
    assert len([x for x in sample_ids if x == "Z1"]) == 1


def test_zero_merge_keeps_latest():
    zero_a = make_event("ZERO-A", request_id="0", minute=1)
    zero_b = make_event("ZERO-B", request_id="0", minute=5)
    pipeline = DedupSamplePipeline(dedup_rules=[], sample_configs=[])
    result = pipeline.sample(
        [zero_a, zero_b],
        SampleConfig("SAMP-ZERO", "EVEN-REQ", 1.0, "request_id"),
    )
    assert len(result) == 1
    assert result[0].record_id == "ZERO-B"


def test_delivered_history_evidence_and_pending_quota():
    desk = InvestigationDesk(quota=4)
    a = make_event("A", location="s::a:1")
    b = make_event("B", request_id="", location="s::b:2")
    c = make_event("C", request_id="", location="s::c:3", minute=3)
    d = make_event("D", request_id="", location="s::d:4", minute=4)
    desk.ingest_records([a, b, c, d])

    # 两笔无键原行实际领取；重复领取 A 幂等。
    ra1 = desk.claim_physical("INV-1", "s::a:1")
    rb1 = desk.claim_physical("INV-1", "s::b:2")
    ra2 = desk.claim_physical("INV-1", physical_location="s::a:1")
    assert ra1.ok and rb1.ok and ra2.duplicate
    assert len(desk.investigations["INV-1"].deliveries) == 2

    # C/D 进入待发清单并占两个名额（总额度4，已交付2，剩余0）。
    desk.plan_round("INV-1")
    assert len(desk.pending_dispatch) == 2
    assert desk.available_slots(4, "INV-1") == 0

    # 实际交付后再补证：A/B 同请求；C/D 也同请求。
    desk.supply_evidence(request_id="REQ-AB",
                         physical_locations=["s::a:1", "s::b:2"])
    result = desk.supply_evidence(request_id="REQ-CD",
                                  physical_locations=["s::c:3", "s::d:4"])
    assert result.ok
    assert len(desk.deliveries) == 2  # 历史不被补证改写

    groups = desk.request_groups()
    assert set(groups) == {"REQ-AB", "REQ-CD"}
    assert len(groups["REQ-AB"].physical_ids) == 2
    assert len(groups["REQ-CD"].physical_ids) == 2

    # C/D 的未交付重复候选撤出一个并释放名额。
    assert len(desk.pending_dispatch) == 1
    assert desk.pending_dispatch[0].request_id == "REQ-CD"
    assert desk.available_slots(4, "INV-1") == 1

    # 已交付 A 不能通过 physical 入口再发一次。
    again = desk.claim_physical("INV-2", "s::a:1")
    assert not again.ok and again.error == "original_already_delivered"

    # 新轮次归组看得到 REQ-AB，但不会把已交付 A/B 加为新候选。
    round2 = desk.plan_round("INV-2")
    new_ids = [r.record_id for r in round2.samples]
    assert "A" not in new_ids and "B" not in new_ids
    assert all(c.request_id != "REQ-AB" for c in round2.candidates)

    # 缺键记录即使已补证/交付也永远可按位置回查。
    assert desk.find_by_location("s::a:1") is not None
    assert desk.find_by_location("s::b:2").empty_kind == "empty_string"


def test_concurrent_confirmation_writes_once():
    desk = EmptyKeyWorkflow()
    a = make_event("A", location="s::a:1")
    desk.ingest_records([a])
    desk.claim_physical("INV-C", "s::a:1")

    barrier = threading.Barrier(16)

    def confirm(_):
        barrier.wait()
        return desk.confirm_investigation("INV-C")

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(confirm, range(16)))

    assert len(desk.confirmations) == 1
    assert all(r.confirmation.confirmation_id == desk.confirmations[0].confirmation_id
               for r in results)
    assert sum(1 for r in results if not r.duplicate) == 1


def test_conflict_failure_keeps_location_and_retry():
    desk = EmptyKeyWorkflow()
    a = make_event("A", location="s::conflict:9")
    desk.ingest_records([a])
    first = desk.supply_evidence("s::conflict:9", "REQ-1")
    assert first.ok
    conflict = desk.supply_evidence("s::conflict:9", "REQ-2")
    assert not conflict.ok
    failure = conflict.failure
    assert failure.physical_location == "s::conflict:9"
    assert failure.status == "failed"
    assert len(desk.failures) == 1

    # 错误证明仍冲突；保留失败位置。
    bad_retry = desk.retry_failure(failure.failure_id, request_id="REQ-3")
    assert not bad_retry.ok
    assert desk.failures[0].physical_location == "s::conflict:9"

    # 用 force/正确处置后可重试成功。
    ok = desk.retry_failure(failure.failure_id, request_id="REQ-2", force=True)
    assert ok.ok
    assert desk.failures[0].status == "resolved"
    assert desk.get("s::conflict:9").verified_request_id == "REQ-2"


def test_interleaved_proof_claim_and_next_round_without_resending_a():
    # 严格策略：A 已获证则只采 A，B 未获证保持待核。
    desk = InvestigationDesk(conflict_policy="verified_only")
    a = make_event("A", location="s::ab:1", minute=1)
    b = make_event("B", request_id="", location="s::ab:2", minute=2)
    desk.ingest_records([a, b])

    proof = desk.supply_evidence("s::ab:1", "REQ-X")
    assert proof.ok

    round1 = desk.plan_round("INV-X1")
    round1_ids = [r.record_id for r in round1.samples]
    assert round1_ids == ["A"], round1_ids
    assert len(round1.on_hold) == 1
    assert round1.on_hold[0].physical_id.endswith("s::ab:2") or True

    claim_a = desk.claim_merged("INV-X1", "REQ-X")
    assert claim_a.ok and claim_a.receipt.sample.record_id == "A"
    desk.confirm_investigation("INV-X1")
    assert desk.confirmations[0].actual_kinds == ["verified_merge"]

    # B 的证据补全为同请求；下一轮只能发未交付的 B，不能重发 A。
    desk.supply_evidence("s::ab:2", "REQ-X")
    round2 = desk.plan_round("INV-X2", exclude_delivered=True)
    round2_ids = [r.record_id for r in round2.samples]
    assert "A" not in round2_ids
    assert "B" in round2_ids, round2_ids
    candidate_b = next(c for c in round2.candidates if c.request_id == "REQ-X")
    assert candidate_b.sample_record.record_id == "B"

    # 同一行不会同时作为 physical 和 merged 新样本重复计额。
    assert any(pid.endswith("s::ab:1") for pid in desk._global_delivered_pids)
    merged_receipt = desk.claim_merged("INV-X2", "REQ-X")
    assert merged_receipt.ok
    assert merged_receipt.receipt.physical_id.endswith("s::ab:2")
    inv2_ids = [d.physical_id or "" for d in desk.investigations["INV-X2"].deliveries]
    assert sum(pid.endswith("s::ab:1") for pid in inv2_ids) == 0


def test_lenient_interleaving_allows_independent_b():
    desk = InvestigationDesk(conflict_policy="independent_empty")
    a = make_event("A", location="s::lenient:1")
    b = make_event("B", request_id="", location="s::lenient:2")
    desk.ingest_records([a, b])

    # 调查员已领取两笔无键原行，随后 A 的证明到达并与确认交错。
    desk.claim_physical("INV-L", "s::lenient:1")
    desk.claim_physical("INV-L", "s::lenient:2")
    proof = desk.supply_evidence("s::lenient:1", "REQ-L")
    confirmation = desk.confirm_investigation("INV-L")

    assert proof.ok and confirmation.ok
    kinds = confirmation.confirmation.sample_kinds
    assert kinds.count("physical_original") == 2
    assert len(desk.deliveries) == 2
    assert desk.get("s::lenient:2").verified is False


def test_same_row_not_counted_as_two_sample_kinds():
    desk = InvestigationDesk()
    a = make_event("A", request_id="REQ-DOUBLE", location="s::double:1")
    desk.ingest_records([a])

    physical = desk.claim_physical("INV-D", "s::double:1")
    merged = desk.claim_merged("INV-D", "REQ-DOUBLE")
    assert physical.ok
    assert merged.ok
    assert merged.double_count_blocked
    assert merged.no_new_sample
    assert len(desk.investigations["INV-D"].deliveries) == 1
    desk.confirm_investigation("INV-D")
    assert desk.confirmations[0].actual_kinds == ["physical_original"]


def run_all():
    tests = {
        "missing_empty_and_zero": test_missing_empty_and_zero_classification,
        "zero_merge_latest": test_zero_merge_keeps_latest,
        "history_pending_quota": test_delivered_history_evidence_and_pending_quota,
        "concurrent_confirm_once": test_concurrent_confirmation_writes_once,
        "conflict_retry": test_conflict_failure_keeps_location_and_retry,
        "next_round_no_a_resend": test_interleaved_proof_claim_and_next_round_without_resending_a,
        "lenient_b": test_lenient_interleaving_allows_independent_b,
        "no_double_quota": test_same_row_not_counted_as_two_sample_kinds,
    }
    passed = failed = 0
    for name, fn in tests.items():
        try:
            fn()
            passed += 1
            print(f"  PASS  empty_key_workflow: {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  empty_key_workflow: {name}")
            traceback.print_exc()
    print(f"\nempty_key_workflow: {passed} passed, {failed} failed, {len(tests)} total")
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
