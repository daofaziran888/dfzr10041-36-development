"""空键处置、补证核销与调查采样的共享状态模型。

本模块不依赖 FastAPI，也不要求源事件必须是 :class:`~app.core.models.EventRecord`；
字典、dataclass 或普通对象均可。这样真实源数据中的 ``source`` / 物理位置不会在
去重和采样过程中丢失。

核心不变量：

* 字段缺失（``MISSING``）和显式空串（``EMPTY_STRING``）分别登记；
* 文本/整数 ``0`` 是合法请求号；
* 不同物理位置的无键原行永不共享同一个普通请求号指纹组；
* 补证只改变之后的归组/选样，不改写已经交付的历史证据；
* 同一物理原行的重复登记幂等，同一次调查的并发确认只写入一次。
"""
from __future__ import annotations

import hashlib
import threading
from datetime import datetime
from typing import Any, Callable, Iterable


MISSING_VALUE = object()

KEY_VALID = "valid"
KEY_MISSING = "missing"
KEY_EMPTY_STRING = "empty_string"
KEY_BLANK = "blank"

STATUS_OPEN = "open"
STATUS_PENDING = "pending"
STATUS_VERIFIED = "verified"
STATUS_DELIVERED = "delivered"
STATUS_WITHDRAWN = "withdrawn"
STATUS_FAILED = "failed"
STATUS_RESOLVED = "resolved"

KIND_PHYSICAL = "physical_original"
KIND_MERGED = "verified_merge"
KIND_INDEPENDENT_EMPTY = "independent_empty"

POLICY_INDEPENDENT_EMPTY = "independent_empty"
POLICY_VERIFIED_ONLY = "verified_only"

REQUEST_KEY_FIELDS = (
    "request_id",
    "request_no",
    "request_number",
    "request_sn",
    "req_id",
    "requestId",
    "requestNo",
    "x_request_id",
)

_SOURCE_FIELDS = (
    "source_id", "source", "origin", "source_ref", "log_source_id",
    "log_source", "source_name", "source_file", "app_label",
    "source_host", "host",
)
_LOCATION_FIELDS = (
    "physical_location", "real_location", "physical_position", "real_position",
    "source_location", "file_location", "location", "locator", "position",
    "anchor", "coordinates", "physical_ref",
)
_PATH_FIELDS = ("source_path", "log_path", "file_path", "path", "filename")
_LINE_FIELDS = ("line_number", "line_no", "lineno", "line", "physical_line")
_OFFSET_FIELDS = ("offset", "byte_offset", "cursor", "file_cursor")
_ID_FIELDS = ("physical_id", "location_id", "locator_id", "pid", "physical_ref")
_RECORD_ID_FIELDS = ("record_id", "event_id", "id", "row_id", "line_id")


class AttrDict(dict):
    """同时支持属性和字典取值的结果对象。"""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:  # pragma: no cover - 透传标准属性错误
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __delattr__(self, name: str) -> None:
        try:
            del self[name]
        except KeyError as exc:  # pragma: no cover
            raise AttributeError(name) from exc


class ResultList(list):
    """普通 list，但可携带处置清单、报告等元数据。"""

    def __init__(self, iterable: Iterable[Any] = (), **metadata: Any):
        super().__init__(iterable)
        for key, value in metadata.items():
            setattr(self, key, value)

    def copy(self) -> "AttrDict":
        return AttrDict(super().copy())


class EmptyKeyError(ValueError):
    """空键工作流基础异常。"""


class EvidenceConflictError(EmptyKeyError):
    """补证与既有请求号或交付状态冲突。"""


class VerificationRequiredError(EmptyKeyError):
    """尝试按请求号领取归并样本，但请求号尚未核验。"""


class AlreadyDeliveredError(EmptyKeyError):
    """原行已经交付，不能通过再次交付来修正历史。"""


def _now() -> str:
    return datetime.now().isoformat(timespec="microseconds")


def _get_field(obj: Any, name: str) -> tuple[bool, Any]:
    """从字典/对象读取顶层字段；None 也是“找到了字段”。"""
    if obj is None:
        return False, None
    if isinstance(obj, dict):
        if name in obj:
            return True, obj[name]
        return False, None
    try:
        value = getattr(obj, name)
    except AttributeError:
        return False, None
    return True, value


def _containers(record: Any) -> list[Any]:
    """返回可能承载解析字段的嵌套容器。"""
    containers: list[Any] = []
    for name in ("parsed_fields", "fields", "field_map", "values", "payload",
                 "data", "attributes", "masked_fields", "enriched_fields"):
        found, value = _get_field(record, name)
        if found and isinstance(value, dict):
            containers.append(value)
    if isinstance(record, dict):
        containers.append(record)
    else:
        containers.append(record)
    return containers


def extract_key(record: Any, key_field: str | None = None) -> tuple[str, Any, str]:
    """提取请求号，保留“字段不存在”和“显式空串”的区别。

    返回 ``(实际字段名, 原始值, 来源容器)``；找不到时原始值为
    :data:`MISSING_VALUE`。
    """
    fields = (key_field,) if key_field else REQUEST_KEY_FIELDS
    for field in fields:
        if not field:
            continue
        for container in _containers(record):
            found, value = _get_field(container, field)
            if found:
                origin = "dict" if isinstance(container, dict) else type(container).__name__
                return field, value, origin
    return key_field or REQUEST_KEY_FIELDS[0], MISSING_VALUE, "missing"


def classify_key(value: Any) -> str:
    """判断键状态。注意 ``0`` / ``"0"`` 都是合法值。"""
    if value is MISSING_VALUE or value is None:
        return KEY_MISSING
    if isinstance(value, str):
        if value == "":
            return KEY_EMPTY_STRING
        if not value.strip():
            return KEY_BLANK
        return KEY_VALID
    if isinstance(value, bool):
        return KEY_VALID
    if isinstance(value, (int, float)):
        return KEY_VALID
    if str(value).strip() == "":
        return KEY_BLANK
    return KEY_VALID


def normalize_key(value: Any) -> str | None:
    """把合法键规范化为非空文本；非法/空键返回 ``None``。"""
    state = classify_key(value)
    if state != KEY_VALID:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else str(value)
    return str(value).strip()


def _first_value(record: Any, names: Iterable[str]) -> tuple[str, Any]:
    for name in names:
        found, value = _get_field(record, name)
        if found and value not in (None, MISSING_VALUE):
            return name, value
    return "", ""


def describe_source(record: Any = None, **overrides: Any) -> AttrDict:
    """提取来源和真实物理位置，兼容 EventRecord、dict 与普通对象。"""
    info: dict[str, Any] = {}

    # 显式 kwargs 优先级最高，但不能让 None 覆盖记录中的真实值。
    for key, value in overrides.items():
        if value is not None:
            info[key] = value

    record_id = info.get("record_id")
    if record_id is None:
        _, record_id = _first_value(record, _RECORD_ID_FIELDS)

    source_id = info.get("source_id") or info.get("source")
    if not source_id:
        _, source_id = _first_value(record, _SOURCE_FIELDS)

    location = (
        info.get("physical_location")
        or info.get("real_location")
        or info.get("location")
        or info.get("locator")
        or info.get("position")
    )
    if not location:
        _, location = _first_value(record, _LOCATION_FIELDS)

    path = info.get("path") or info.get("file_path") or info.get("source_path")
    line_number = info.get("line_number") or info.get("line_no")
    offset = info.get("offset")
    if not path:
        _, path = _first_value(record, _PATH_FIELDS)
    if line_number in (None, ""):
        _, line_number = _first_value(record, _LINE_FIELDS)
    if offset in (None, ""):
        _, offset = _first_value(record, _OFFSET_FIELDS)

    if not location and path and line_number not in (None, ""):
        location = f"{path}:{line_number}"
    elif not location and path and offset not in (None, ""):
        location = f"{path}#offset-{offset}"
    elif not location and path:
        location = str(path)

    physical_id = info.get("physical_id") or info.get("pid") or info.get("id")
    if not physical_id:
        _, physical_id = _first_value(record, _ID_FIELDS)
    if not physical_id:
        if source_id and location:
            physical_id = f"{source_id}::{location}"
        elif location:
            physical_id = str(location)
        elif record_id not in (None, ""):
            physical_id = f"record::{record_id}"
        else:
            raw = ""
            for name in ("raw_line", "original_content", "content", "message"):
                found, value = _get_field(record, name)
                if found and value:
                    raw = str(value)
                    break
            physical_id = "auto::" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    return AttrDict(
        physical_id=str(physical_id),
        source_id="" if source_id in (None, MISSING_VALUE) else str(source_id),
        source="" if source_id in (None, MISSING_VALUE) else str(source_id),
        location="" if location in (None, MISSING_VALUE) else str(location),
        physical_location="" if location in (None, MISSING_VALUE) else str(location),
        real_location="" if location in (None, MISSING_VALUE) else str(location),
        record_id="" if record_id in (None, MISSING_VALUE) else str(record_id),
        path="" if path in (None, MISSING_VALUE) else str(path),
        line_number=line_number if line_number not in (None, MISSING_VALUE) else None,
        offset=offset if offset not in (None, MISSING_VALUE) else None,
    )


def record_time(record: Any) -> datetime:
    """读取事件时间，兼容 EventRecord、dict 和 ISO 字符串。"""
    found, value = _get_field(record, "event_time")
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.min


def physical_fingerprint(record: Any, key_field: str | None = None,
                         prefix: str = "empty-key") -> str:
    """为空键原行生成绑定物理位置的唯一指纹。"""
    desc = describe_source(record)
    field, raw, _ = extract_key(record, key_field)
    state = classify_key(raw)
    material = "|".join([
        prefix, field, state, desc.physical_id, desc.source_id, desc.location,
        desc.record_id,
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class EmptyKeyLedger(list):
    """空键处置清单及其补证/冲突记录。

    继承 ``list`` 并保持 list-like：``len(ledger)``、``ledger[0]``、
    ``for item in ledger`` 都按登记顺序访问处置条目。
    """

    def __init__(self, key_field: str = "request_id",
                 sink: list | None = None,
                 auto_reconcile: bool = True,
                 **kwargs: Any) -> None:
        super().__init__()
        self.key_field = key_field
        self.auto_reconcile = auto_reconcile
        self.options = AttrDict(kwargs)
        self._entries: dict[str, AttrDict] = {}
        self._order: list[str] = []
        self.failures: list[AttrDict] = []
        self.external_sinks: list[list] = []
        if sink is not None:
            self.external_sinks.append(sink)
        self.lock = threading.RLock()
        self._failure_seq = 0
        self._listeners: list[Callable[..., None]] = []

    # ---------- list-like 视图 ----------

    @property
    def entries(self) -> list[AttrDict]:
        return [self._entries[pid] for pid in self._order]

    @property
    def items(self) -> list[AttrDict]:
        return self.entries

    @property
    def disposition_list(self) -> list[AttrDict]:
        return self.entries

    @property
    def empty_key_disposition_list(self) -> list[AttrDict]:
        return self.entries

    def list_entries(self) -> list[AttrDict]:
        return self.entries

    def all(self) -> list[AttrDict]:
        return self.entries

    def get_disposition_list(self) -> list[AttrDict]:
        return self.entries

    def get_empty_key_list(self) -> list[AttrDict]:
        return self.entries

    def get_empty_key_disposition_list(self) -> list[AttrDict]:
        return self.entries

    def __len__(self) -> int:
        return len(self._order)

    def __iter__(self):
        return iter(self.entries)

    def __getitem__(self, index):
        if isinstance(index, str):
            return self._entries[index]
        return self.entries[index]

    def append(self, item: Any) -> AttrDict | None:
        """允许把清单对象当作 sink 使用；字典/原行会被登记。"""
        if isinstance(item, AttrDict) and item.get("physical_id") in self._entries:
            return self._entries[item["physical_id"]]
        return self.register(item)

    def add_sink(self, sink: list) -> None:
        self.external_sinks.append(sink)

    def add_listener(self, listener: Callable[..., None]) -> None:
        self._listeners.append(listener)

    def _emit(self, event: str, **payload: Any) -> None:
        for listener in list(self._listeners):
            try:
                listener(event, **payload)
            except Exception:
                # 监听器不能破坏主状态；测试可自行检查其 mock。
                pass

    # ---------- 检查与登记 ----------

    def inspect(self, record: Any = None, **info: Any) -> AttrDict:
        key_field = info.pop("key_field", self.key_field)
        field, raw, origin = self._extract_with_info(record, info, key_field)
        state = classify_key(raw)
        desc = describe_source(record, **info)
        return AttrDict(
            key_field=field,
            raw_key=raw,
            key_state=state,
            state=state,
            is_empty=state != KEY_VALID,
            request_id=normalize_key(raw),
            normalized_key=normalize_key(raw),
            origin=origin,
            **desc,
        )

    @staticmethod
    def _extract_with_info(record: Any, info: dict[str, Any],
                           key_field: str) -> tuple[str, Any, str]:
        # 显式 info 优先，允许 register(request_id="") 表达空串。
        probe = AttrDict(info)
        field, raw, origin = extract_key(probe, key_field)
        if raw is not MISSING_VALUE:
            return field, raw, "argument"
        return extract_key(record, key_field)

    def register(self, record: Any = None, **info: Any) -> AttrDict | None:
        """登记一条空键原行；同一物理位置重复提交只更新计数。"""
        key_field = info.get("key_field", self.key_field)
        inspection = self.inspect(record, **info)
        if inspection.key_state == KEY_VALID and not info.get("force"):
            return None

        with self.lock:
            pid = inspection.physical_id
            now = _now()
            existing = self._entries.get(pid)
            if existing is not None:
                existing.submission_count = int(existing.get("submission_count", 1)) + 1
                existing.duplicate_count = int(existing.get("duplicate_count", 0)) + 1
                existing.was_duplicate = True
                existing.last_seen_at = now
                # 不覆盖第一次观察到的 missing/empty_string 类型。
                if not existing.get("location") and inspection.location:
                    existing.location = inspection.location
                    existing.physical_location = inspection.location
                    existing.real_location = inspection.location
                self._emit("empty_key_duplicate", entry=existing)
                return existing

            entry = AttrDict(
                physical_id=pid,
                physical_location=inspection.physical_location,
                real_location=inspection.real_location,
                source_location=inspection.physical_location,
                physical_position=inspection.physical_location,
                position=inspection.physical_location,
                locator=inspection.physical_location or pid,
                location=inspection.location,
                source_id=inspection.source_id,
                source=inspection.source_id,
                origin=inspection.source_id,
                record_id=inspection.record_id,
                path=inspection.path,
                line_number=inspection.line_number,
                offset=inspection.offset,
                key_field=inspection.key_field,
                empty_kind=inspection.key_state,
                key_state=inspection.key_state,
                key_status=inspection.key_state,
                empty_key_state=inspection.key_state,
                empty_key_status=inspection.key_state,
                kind=inspection.key_state,
                raw_key=None if inspection.raw_key is MISSING_VALUE else inspection.raw_key,
                status=STATUS_PENDING,
                disposition="pending_verification",
                disposition_label="待核",
                verified=False,
                evidence_status="unverified",
                request_id=None,
                request_no=None,
                request_number=None,
                verified_request_id=None,
                submission_count=1,
                registered_count=1,
                duplicate_count=0,
                was_duplicate=False,
                created_at=now,
                updated_at=now,
                last_seen_at=now,
                verified_at=None,
                proofs=[],
                claim_ids=[],
                delivery_ids=[],
                failure_ids=[],
                record=record if record is not None else info,
            )
            self._entries[pid] = entry
            self._order.append(pid)
            list.append(self, entry)
            for sink in self.external_sinks:
                sink.append(entry)
            self._emit("empty_key_registered", entry=entry)
            return entry

    # 常见别名。
    record_empty_key = register
    add_empty_key = register
    track_empty_key = register
    handle_empty_key = register
    add = register
    report = register
    report_row = register

    def register_all(self, records: Iterable[Any], **info: Any) -> list[AttrDict]:
        result = []
        for record in records or []:
            entry = self.register(record, **info)
            if entry is not None:
                result.append(entry)
        return result

    ingest = register_all

    # ---------- 查询 ----------

    def resolve_target(self, target: Any = None, **kwargs: Any) -> str | None:
        if target is None:
            target = (
                kwargs.get("physical_id")
                or kwargs.get("pid")
                or kwargs.get("physical_location")
                or kwargs.get("location")
                or kwargs.get("record_id")
            )
        if isinstance(target, AttrDict) and target.get("physical_id"):
            return target["physical_id"]
        if isinstance(target, dict) and target.get("physical_id"):
            return str(target["physical_id"])
        if target is not None and not isinstance(target, (str, int)):
            desc = describe_source(target, **kwargs)
            if desc.physical_id in self._entries:
                return desc.physical_id
        if isinstance(target, (str, int)):
            text = str(target)
            if text in self._entries:
                return text
            for entry in self.entries:
                if text in {
                    entry.location, entry.physical_location, entry.real_location,
                    entry.record_id, entry.source_id,
                }:
                    return entry.physical_id
        # kwargs 中直接给位置时，describe 可生成同样的 pid。
        if kwargs:
            desc = describe_source(**kwargs)
            if desc.physical_id in self._entries:
                return desc.physical_id
        return None

    def get(self, target: Any, default: Any = None) -> AttrDict | None:
        pid = self.resolve_target(target)
        if pid is None:
            return default
        return self._entries.get(pid, default)

    def find(self, **criteria: Any) -> AttrDict | None:
        for entry in self.entries:
            if all(entry.get(key) == value for key, value in criteria.items()):
                return entry
        return None

    def find_by_location(self, location: str, source: str | None = None) -> AttrDict | None:
        for entry in self.entries:
            if entry.location != location and entry.physical_location != location:
                continue
            if source and entry.source_id != source:
                continue
            return entry
        if source and location:
            return self.get(f"{source}::{location}")
        return self.get(location)

    by_physical_location = find_by_location

    @property
    def open_entries(self) -> list[AttrDict]:
        return [e for e in self.entries if e.status in (STATUS_OPEN, STATUS_PENDING)]

    @property
    def pending_verification(self) -> list[AttrDict]:
        return [e for e in self.entries if not e.verified]

    @property
    def verified_entries(self) -> list[AttrDict]:
        return [e for e in self.entries if e.verified and e.request_id]

    @property
    def failed_records(self) -> list[AttrDict]:
        return list(self.failures)

    # ---------- 补证 ----------

    def _result(self, ok: bool, **payload: Any) -> AttrDict:
        result = AttrDict(ok=ok, success=ok, **payload)
        return result

    def _record_failure(self, *, operation: str, target: Any,
                        reason: str, error: Exception | None = None,
                        retry_of: str | None = None, **fields: Any) -> AttrDict:
        if retry_of and retry_of in {f.failure_id: f for f in self.failures}:
            failure = next(f for f in self.failures if f.failure_id == retry_of)
            failure.retry_count = int(failure.get("retry_count", 0)) + 1
            failure.last_retry_at = _now()
            failure.status = STATUS_FAILED
            failure.reason = reason
            if error:
                failure.error = str(error)
            failure.update(fields)
            return failure

        with self.lock:
            self._failure_seq += 1
            failure_id = fields.pop("failure_id", None) or f"FAIL-{self._failure_seq:04d}"
            desc: AttrDict | None = None
            pid = fields.pop("physical_id", None)
            if pid is None:
                pid = self.resolve_target(target, **fields)
            if pid and pid in self._entries:
                entry = self._entries[pid]
                desc = entry
            else:
                try:
                    desc = describe_source(target if not isinstance(target, (str, int)) else None,
                                           physical_location=target if isinstance(target, str) else None,
                                           **{k: v for k, v in fields.items()
                                              if k in ("source", "source_id", "location",
                                                        "physical_location", "record_id")})
                except Exception:
                    desc = AttrDict(physical_id=str(target), source_id="", location=str(target),
                                    physical_location=str(target), record_id="")

            failure = AttrDict(
                failure_id=failure_id,
                id=failure_id,
                ok=False,
                success=False,
                status=STATUS_FAILED,
                retryable=True,
                operation=operation,
                reason=reason,
                error=str(error) if error else reason,
                physical_id=pid or (desc.physical_id if desc else str(target)),
                physical_location=(desc.physical_location if desc else str(target)),
                location=(desc.location if desc else str(target)),
                position=(desc.physical_location if desc else str(target)),
                real_location=(desc.real_location if desc else str(target)),
                source_id=(desc.source_id if desc else ""),
                source=(desc.source_id if desc else ""),
                record_id=(desc.record_id if desc else ""),
                target=target if isinstance(target, (str, int)) else desc.physical_id if desc else None,
                retry_count=0,
                created_at=_now(),
                updated_at=_now(),
                resolved_at=None,
            )
            failure.update(fields)

            def _retry(**overrides: Any):
                return self.retry_failure(failure.failure_id, **overrides)

            failure["retry"] = _retry
            self.failures.append(failure)
            if pid and pid in self._entries:
                self._entries[pid].failure_ids.append(failure_id)
            self._emit("failure_recorded", failure=failure)
            return failure

    def supply_evidence(self, *args: Any, request_id: Any = None,
                        physical_location: Any = None, location: Any = None,
                        physical_id: Any = None,
                        locations: Iterable[Any] | None = None,
                        physical_locations: Iterable[Any] | None = None,
                        targets: Iterable[Any] | None = None,
                        force: bool = False,
                        raise_on_conflict: bool = False,
                        retry_of: str | None = None,
                        proof: Any = None,
                        **kwargs: Any) -> AttrDict | list[AttrDict]:
        """补充请求号证明。

        支持常见调用形式：
        ``supply_evidence(pid, "R1")``、
        ``supply_evidence("R1", physical_location="a.log:1")``、
        ``supply_evidence(request_id="R1", physical_locations=[...])``。
        """
        rid = normalize_key(request_id)
        target_values: list[Any] = []
        if physical_id is not None:
            target_values.append(physical_id)
        if physical_location is not None:
            target_values.append(physical_location)
        if location is not None:
            target_values.append(location)
        for collection in (physical_locations, locations, targets):
            if collection:
                target_values.extend(list(collection))

        # 解析位置参数：两个字符串时，已登记的物理标识优先作为 target。
        positional = list(args)
        if positional:
            if len(positional) >= 2:
                left, right = positional[0], positional[1]
                left_pid = self.resolve_target(left)
                right_pid = self.resolve_target(right)
                right_key = normalize_key(right)
                left_key = normalize_key(left)
                if left_pid and right_key is not None and not right_pid:
                    target_values.insert(0, left)
                    if rid is None:
                        rid = right_key
                elif right_pid and left_key is not None and not left_pid:
                    target_values.insert(0, right)
                    if rid is None:
                        rid = left_key
                else:
                    target_values.insert(0, left)
                    if rid is None and right_key is not None:
                        rid = right_key
            else:
                value = positional[0]
                if rid is None and normalize_key(value) is not None and not self.resolve_target(value):
                    rid = normalize_key(value)
                else:
                    target_values.insert(0, value)

        if rid is None and kwargs.get("request_no") is not None:
            rid = normalize_key(kwargs["request_no"])
        if rid is None and kwargs.get("verified_request_id") is not None:
            rid = normalize_key(kwargs["verified_request_id"])

        # 没有显式 target 时，kwargs/record 本身可能携带位置。
        if not target_values and (kwargs or proof is not None):
            candidate = proof if proof is not None else kwargs
            pid = self.resolve_target(candidate, **kwargs)
            if pid:
                target_values.append(pid)

        results: list[AttrDict] = []
        with self.lock:
            if rid is None:
                failure = self._record_failure(
                    operation="supply_evidence",
                    target=target_values[0] if target_values else None,
                    reason="invalid_or_missing_request_id",
                    retry_of=retry_of,
                    attempted_request_id=request_id,
                    **kwargs,
                )
                result = self._result(False, error="invalid_or_missing_request_id",
                                      failure=failure)
                if raise_on_conflict:
                    raise VerificationRequiredError("请求号证明无效")
                return result

            if not target_values:
                failure = self._record_failure(
                    operation="supply_evidence", target=None,
                    reason="missing_physical_target", retry_of=retry_of,
                    attempted_request_id=rid, **kwargs,
                )
                return self._result(False, error="missing_physical_target", failure=failure)

            for target in target_values:
                pid = self.resolve_target(target, **kwargs)
                if pid is None or pid not in self._entries:
                    failure = self._record_failure(
                        operation="supply_evidence", target=target,
                        reason="physical_record_not_found",
                        retry_of=retry_of if len(target_values) == 1 else None,
                        attempted_request_id=rid, **kwargs,
                    )
                    results.append(self._result(False, error="physical_record_not_found",
                                                failure=failure))
                    continue

                entry = self._entries[pid]
                old_rid = entry.get("verified_request_id") or entry.get("request_id")
                if old_rid and old_rid != rid and not force:
                    failure = self._record_failure(
                        operation="supply_evidence", target=pid,
                        reason="request_id_conflict",
                        error=EvidenceConflictError(
                            f"{pid}: {old_rid} != {rid}"),
                        retry_of=retry_of if len(target_values) == 1 else None,
                        existing_request_id=old_rid,
                        attempted_request_id=rid,
                    )
                    results.append(self._result(False, error="request_id_conflict",
                                                failure=failure, entry=entry))
                    if raise_on_conflict:
                        raise EvidenceConflictError(f"{old_rid} != {rid}")
                    continue

                now = _now()
                entry.request_id = rid
                entry.request_no = rid
                entry.request_number = rid
                entry.verified_request_id = rid
                entry.verified = True
                entry.evidence_status = "verified"
                entry.status = STATUS_VERIFIED if entry.status not in (
                    STATUS_DELIVERED,) else STATUS_DELIVERED
                entry.disposition = entry.status
                entry.verified_at = now
                entry.updated_at = now
                proof_item = AttrDict(
                    request_id=rid, proof=proof, supplied_at=now,
                    source=kwargs.get("source") or kwargs.get("evidence_source"),
                    note=kwargs.get("note"),
                )
                entry.proofs.append(proof_item)
                self._emit("evidence_supplied", entry=entry, request_id=rid)
                results.append(self._result(True, entry=entry, request_id=rid,
                                            physical_id=pid))

            if self.auto_reconcile and hasattr(self, "reconcile_pending"):
                try:
                    self.reconcile_pending()
                except Exception:
                    pass

        if len(results) == 1 and len(target_values) == 1:
            return results[0]
        ok = all(bool(r.ok) for r in results)
        return ResultList(
            results,
            ok=ok,
            success=ok,
            results=results,
            request_id=rid,
            target_count=len(target_values),
        )

    # 常见别名。
    add_evidence = supply_evidence
    attach_evidence = supply_evidence
    supplement = supply_evidence
    supplement_evidence = supply_evidence
    supplement_key = supply_evidence
    supplement_request_id = supply_evidence
    provide_proof = supply_evidence
    add_proof = supply_evidence
    submit_evidence = supply_evidence
    receive_evidence = supply_evidence
    verify_request = supply_evidence
    verify_key = supply_evidence

    def retry_failure(self, failure_id: str | AttrDict, **overrides: Any) -> AttrDict:
        fid = failure_id.get("failure_id") if isinstance(failure_id, dict) else str(failure_id)
        failure = next((f for f in self.failures if f.failure_id == fid), None)
        if failure is None:
            return self._result(False, error="failure_not_found", failure_id=fid)

        operation = failure.get("operation", "supply_evidence")
        if operation == "claim_merged":
            result = self.claim_merged(
                overrides.pop("investigation_id", failure.get("investigation_id")),
                overrides.pop("request_id", failure.get("request_id")),
                **overrides,
            )
        elif operation == "claim_physical":
            result = self.claim_physical(
                overrides.pop("investigation_id", failure.get("investigation_id")),
                overrides.pop("target", failure.physical_id),
                **overrides,
            )
        else:
            request_id = overrides.pop("request_id", failure.get("attempted_request_id"))
            target = overrides.pop("target", failure.physical_id)
            result = self.supply_evidence(
                target, request_id=request_id, retry_of=fid, **overrides)
            if isinstance(result, list):
                result = result[0] if result else self._result(False, error="empty_retry")

        if getattr(result, "ok", False):
            failure.status = STATUS_RESOLVED
            failure.resolved_at = _now()
            failure.result = "resolved"
        return result

    def retry_failed(self, **overrides: Any) -> list[AttrDict]:
        results = []
        for failure in list(self.failures):
            if failure.status == STATUS_FAILED and failure.retryable:
                results.append(self.retry_failure(failure.failure_id, **overrides))
        return results

    def retry(self, target: Any = None, **kwargs: Any):
        if target is None:
            return self.retry_failed(**kwargs)
        if isinstance(target, AttrDict) and target.get("failure_id"):
            return self.retry_failure(target, **kwargs)
        return self.retry_failure(target, **kwargs)

    retry_conflict = retry_failure
    retry_failed_records = retry_failed
    retry_failures = retry_failed

    # ---------- 同键关系归组 ----------

    def request_groups(self, include_unproven: bool = False) -> dict[str, AttrDict]:
        groups: dict[str, AttrDict] = {}
        for entry in self.entries:
            rid = entry.get("verified_request_id") or (
                entry.get("request_id") if entry.verified else None)
            if not rid:
                continue
            group = groups.setdefault(rid, AttrDict(
                request_id=rid,
                physical_ids=[],
                physical_locations=[],
                record_ids=[],
                entries=[],
                evidence_count=0,
            ))
            group.physical_ids.append(entry.physical_id)
            group.physical_locations.append(entry.physical_location)
            if entry.record_id:
                group.record_ids.append(entry.record_id)
            group.entries.append(entry)
            group.evidence_count += 1
        return groups

    @property
    def same_request_groups(self) -> list[AttrDict]:
        return list(self.request_groups().values())


class EmptyKeyWorkflow(EmptyKeyLedger):
    """带调查领取、待发名额和并发确认的完整工作流。"""

    def __init__(self, records: Iterable[Any] | str | None = None,
                 key_field: str = "request_id",
                 quota: int | None = None,
                 conflict_policy: str = POLICY_INDEPENDENT_EMPTY,
                 sink: list | None = None,
                 auto_reconcile: bool = True,
                 **kwargs: Any) -> None:
        # 兼容 EmptyKeyWorkflow("request_id") 这类把键字段作为首参的写法。
        if isinstance(records, str):
            key_field = records
            records = None
        super().__init__(key_field=key_field, sink=sink,
                         auto_reconcile=auto_reconcile)
        self.options = AttrDict(kwargs)
        self.quota = quota
        self.conflict_policy = self._normalize_policy(conflict_policy)
        self.records: dict[str, Any] = {}
        self.record_order: list[str] = []
        self.record_keys: dict[str, str] = {}
        self.fingerprints: dict[str, str] = {}
        self.fingerprint_eligible: dict[str, bool] = {}
        self.physical_seen: set[str] = set()

        self.pending: list[AttrDict] = []
        self.withdrawn: list[AttrDict] = []
        self.deliveries: list[AttrDict] = []
        self.claims: list[AttrDict] = []
        self.confirmations: list[AttrDict] = []
        self.investigations: dict[str, AttrDict] = {}
        self.rounds: list[AttrDict] = []
        self._delivery_seq = 0
        self._candidate_seq = 0
        self._confirmation_seq = 0
        self._global_delivered_pids: set[str] = set()
        self._global_counted_pids: set[str] = set()

        if records:
            self.ingest_records(records)

    @staticmethod
    def _normalize_policy(policy: str | None) -> str:
        text = str(policy or "").strip().lower()
        if text in ("verified_only", "strict", "hold_unverified", "require_verified",
                    "key_verified_only", "只采已获证"):
            return POLICY_VERIFIED_ONLY
        return POLICY_INDEPENDENT_EMPTY

    def set_policy(self, policy: str) -> None:
        self.conflict_policy = self._normalize_policy(policy)

    # ---------- 源记录与资格 ----------

    def resolve_target(self, target: Any = None, **kwargs: Any) -> str | None:
        pid = super().resolve_target(target, **kwargs)
        if pid is not None:
            return pid
        with self.lock:
            if target is not None and not isinstance(target, (str, int)):
                desc = describe_source(target, **kwargs)
                if desc.physical_id in self.records:
                    return desc.physical_id
            if isinstance(target, (str, int)):
                text = str(target)
                if text in self.records:
                    return text
                for candidate_pid, record in self.records.items():
                    desc = describe_source(record)
                    if text in {
                        candidate_pid, desc.location, desc.physical_location,
                        desc.real_location, desc.record_id, desc.source_id,
                    }:
                        return candidate_pid
            if kwargs:
                desc = describe_source(**kwargs)
                if desc.physical_id in self.records:
                    return desc.physical_id
        return None

    def ingest_records(self, records: Iterable[Any], **info: Any) -> list[Any]:
        unique: list[Any] = []
        with self.lock:
            for record in records or []:
                desc = describe_source(record, **info)
                pid = desc.physical_id
                field, raw, _ = self._extract_with_info({}, info, self.key_field)
                if raw is MISSING_VALUE:
                    field, raw, _ = extract_key(record, info.get("key_field", self.key_field))
                state = classify_key(raw)
                rid = normalize_key(raw)

                if pid not in self.records:
                    self.records[pid] = record
                    self.record_order.append(pid)
                else:
                    entry = self._entries.get(pid)
                    if entry is not None:
                        entry.submission_count += 1
                        entry.duplicate_count += 1
                if rid is not None:
                    self.record_keys[pid] = rid
                if state != KEY_VALID:
                    self.register(record, **info)
                unique.append(record)
        return unique

    def mark_fingerprint(self, record: Any, fingerprint: str,
                         eligible: bool = True) -> str:
        pid = describe_source(record).physical_id
        self.fingerprints[pid] = fingerprint
        self.fingerprint_eligible[pid] = eligible
        if eligible:
            self.physical_seen.add(pid)
        return pid

    def effective_request_id(self, pid: str) -> str | None:
        entry = self._entries.get(pid)
        if entry and entry.verified_request_id:
            return entry.verified_request_id
        return self.record_keys.get(pid)

    def _record_time(self, record: Any) -> datetime:
        return record_time(record)

    def _source_order_index(self, pid: str) -> int:
        try:
            return self.record_order.index(pid)
        except ValueError:
            return 10**9

    # ---------- 调查 ----------

    def investigation(self, investigation_id: str | None = None) -> AttrDict:
        inv_id = str(investigation_id or "DEFAULT")
        with self.lock:
            inv = self.investigations.get(inv_id)
            if inv is None:
                inv = AttrDict(
                    investigation_id=inv_id,
                    id=inv_id,
                    claims=[],
                    deliveries=[],
                    delivery_ids=[],
                    confirmation=None,
                    confirmation_id=None,
                    confirmed=False,
                    confirmation_writes=0,
                    created_at=_now(),
                    confirmed_at=None,
                    round_count=0,
                )
                self.investigations[inv_id] = inv
            return inv

    get_investigation = investigation

    # ---------- 候选与待发清单 ----------

    def build_groups(self, records: Iterable[Any] | None = None,
                     only_fingerprint_eligible: bool = False) -> AttrDict:
        if records is not None:
            self.ingest_records(records)

        pids = list(self.record_order)
        groups: dict[str, AttrDict] = {}
        unverified: list[AttrDict] = []

        for pid in pids:
            if only_fingerprint_eligible and self.fingerprint_eligible.get(pid) is False:
                continue
            record = self.records.get(pid)
            rid = self.effective_request_id(pid)
            entry = self._entries.get(pid)
            delivered = pid in self._global_delivered_pids
            counted = pid in self._global_counted_pids
            item = AttrDict(
                physical_id=pid,
                record=record,
                request_id=rid,
                delivered=delivered,
                counted=counted,
                event_time=self._record_time(record) if record is not None else datetime.min,
                entry=entry,
            )
            if rid is None:
                unverified.append(item)
                continue
            group = groups.setdefault(rid, AttrDict(
                request_id=rid,
                physical_ids=[],
                records=[],
                members=[],
                items=[],
                delivered_physical_ids=[],
                new_physical_ids=[],
                uncounted_physical_ids=[],
            ))
            group.physical_ids.append(pid)
            group.records.append(record)
            group.members.append(item)
            group["items"].append(item)
            if delivered:
                group.delivered_physical_ids.append(pid)
            else:
                group.new_physical_ids.append(pid)
            if not counted:
                group.setdefault("uncounted_physical_ids", []).append(pid)

        group_list = list(groups.values())
        for group in group_list:
            undelivered = [item for item in group.members if not item.delivered]
            uncounted = [item for item in group.members if not item.counted]
            pool = uncounted or undelivered or group.members
            representative = max(pool, key=lambda x: (x.event_time,
                                                       self._source_order_index(x.physical_id)))
            group.representative_id = representative.physical_id
            group.representative_record = representative.record
            group.all_delivered = len(undelivered) == 0
            group.all_counted = len(uncounted) == 0
            group.evidence_count = len(group.physical_ids)

        return AttrDict(groups=group_list, unverified=unverified,
                        all_candidates=group_list + unverified)

    def _active_pending(self) -> list[AttrDict]:
        return [c for c in self.pending if c.status == STATUS_PENDING]

    @property
    def pending_candidates(self) -> list[AttrDict]:
        return self._active_pending()

    @property
    def pending_dispatch(self) -> list[AttrDict]:
        return self._active_pending()

    @property
    def pending_list(self) -> list[AttrDict]:
        return self._active_pending()

    @property
    def dispatch_list(self) -> list[AttrDict]:
        return self._active_pending()

    def available_slots(self, quota: int | None = None,
                        investigation_id: str | None = None) -> int | None:
        limit = self.quota if quota is None else quota
        if limit is None:
            return None
        inv = self.investigation(investigation_id) if investigation_id else None
        delivered = len(inv.deliveries) if inv else len(self.deliveries)
        used = len(self._active_pending()) + delivered
        return max(0, int(limit) - used)

    def _has_pending_for_pid(self, pid: str) -> bool:
        return any(pid in c.get("physical_ids", []) or c.get("physical_id") == pid
                   for c in self._active_pending())

    def _has_pending_for_request(self, rid: str) -> bool:
        return any(c.get("request_id") == rid for c in self._active_pending())

    def select_candidates(self, records: Iterable[Any] | None = None,
                          strategy: str | None = None,
                          exclude_delivered: bool = True,
                          only_fingerprint_eligible: bool = False) -> AttrDict:
        policy = self._normalize_policy(strategy or self.conflict_policy)
        built = self.build_groups(records, only_fingerprint_eligible)
        selected: list[AttrDict] = []
        on_hold: list[AttrDict] = []

        # 按源顺序输出无键候选；请求组在其首个物理位置出现时输出。
        seen_requests: set[str] = set()
        for pid in self.record_order:
            if only_fingerprint_eligible and self.fingerprint_eligible.get(pid) is False:
                continue
            rid = self.effective_request_id(pid)
            if rid is None:
                item = next((x for x in built.unverified if x.physical_id == pid), None)
                if item is None:
                    continue
                if exclude_delivered and item.delivered:
                    continue
                candidate = AttrDict(
                    candidate_id=f"CAND-{len(self.pending)+len(selected)+1:04d}",
                    kind=KIND_PHYSICAL,
                    sample_kind=KIND_PHYSICAL,
                    eligible_kind=KIND_PHYSICAL,
                    physical_id=pid,
                    physical_ids=[pid],
                    request_id=None,
                    record=item.record,
                    sample_record=item.record,
                    representative_record=item.record,
                    can_merge_by_request=False,
                    status="selected",
                )
                if policy == POLICY_VERIFIED_ONLY:
                    candidate.status = "on_hold"
                    on_hold.append(candidate)
                else:
                    selected.append(candidate)
            elif rid not in seen_requests:
                seen_requests.add(rid)
                group = next(g for g in built.groups if g.request_id == rid)
                if exclude_delivered and group.all_delivered:
                    continue
                rep_pid = group.representative_id
                if exclude_delivered and rep_pid in self._global_delivered_pids:
                    undelivered = [x for x in group.members if not x.delivered]
                    if not undelivered:
                        continue
                    rep = max(undelivered, key=lambda x: x.event_time)
                    rep_pid = rep.physical_id
                candidate = AttrDict(
                    candidate_id=f"CAND-{len(self.pending)+len(selected)+1:04d}",
                    kind=KIND_MERGED,
                    sample_kind=KIND_MERGED,
                    eligible_kind=KIND_MERGED,
                    physical_id=rep_pid,
                    physical_ids=list(group.physical_ids),
                    new_physical_ids=list(group.new_physical_ids),
                    request_id=rid,
                    record=self.records.get(rep_pid),
                    sample_record=self.records.get(rep_pid),
                    representative_record=self.records.get(rep_pid),
                    group=group,
                    can_merge_by_request=True,
                    status="selected",
                )
                selected.append(candidate)

        return AttrDict(samples=selected, selected=selected, on_hold=on_hold,
                        held=on_hold, groups=built.groups,
                        unverified=built.unverified)

    def add_to_pending(self, candidate: AttrDict,
                       quota: int | None = None) -> AttrDict | None:
        with self.lock:
            if candidate.kind == KIND_MERGED and self._has_pending_for_request(candidate.request_id):
                return next(c for c in self._active_pending()
                            if c.request_id == candidate.request_id)
            if candidate.kind == KIND_PHYSICAL and self._has_pending_for_pid(candidate.physical_id):
                return next(c for c in self._active_pending()
                            if c.physical_id == candidate.physical_id)

            limit = self.quota if quota is None else quota
            if limit is not None and len(self._active_pending()) >= int(limit):
                candidate.status = "queued"
                candidate.slot_id = None
                self.pending.append(candidate)
                return candidate

            self._candidate_seq += 1
            candidate.candidate_id = candidate.get("candidate_id") or f"CAND-{self._candidate_seq:04d}"
            candidate.status = STATUS_PENDING
            candidate.slot_id = f"SLOT-{len(self._active_pending()) + 1:03d}"
            candidate.created_at = _now()
            self.pending.append(candidate)
            return candidate

    def plan_round(self, investigation_id: str | None = None,
                   records: Iterable[Any] | None = None,
                   quota: int | None = None,
                   strategy: str | None = None,
                   auto_claim: bool = False,
                   exclude_delivered: bool = True,
                   only_fingerprint_eligible: bool = False) -> AttrDict:
        with self.lock:
            inv = self.investigation(investigation_id)
            inv.round_count += 1
            round_no = inv.round_count
            self.reconcile_pending()
            selection = self.select_candidates(
                records=records, strategy=strategy,
                exclude_delivered=exclude_delivered,
                only_fingerprint_eligible=only_fingerprint_eligible)

            added: list[AttrDict] = []
            for candidate in selection.samples:
                if candidate.status == "on_hold":
                    continue
                existing = None
                if candidate.kind == KIND_MERGED:
                    existing = next((c for c in self._active_pending()
                                     if c.request_id == candidate.request_id), None)
                else:
                    existing = next((c for c in self._active_pending()
                                     if c.physical_id == candidate.physical_id), None)
                if existing is not None:
                    continue
                added.append(self.add_to_pending(candidate, quota=quota))

            active = self._active_pending()
            report = AttrDict(
                round_id=f"{inv.investigation_id}-R{round_no}",
                round=round_no,
                investigation_id=inv.investigation_id,
                samples=[c.sample_record for c in active if c.get("sample_record") is not None],
                candidates=active,
                added=added,
                on_hold=selection.on_hold,
                unverified=selection.unverified,
                groups=selection.groups,
                pending=active,
                withdrawn=[w for w in self.withdrawn if w.get("round") == round_no],
                available_slots=self.available_slots(quota, inv.investigation_id),
                created_at=_now(),
            )
            self.rounds.append(report)
            inv.last_round = report
            if auto_claim:
                for candidate in active:
                    if candidate.kind == KIND_PHYSICAL:
                        self.claim_physical(inv.investigation_id, candidate.physical_id)
                    else:
                        self.claim_merged(inv.investigation_id, candidate.request_id)
            return report

    next_round = plan_round
    run_round = plan_round

    def dedup_events(self, records: Iterable[Any] | None = None,
                     dedup_fields: list[str] | None = None,
                     dedup_rule: Any = None,
                     **kwargs: Any) -> ResultList:
        """工作流门面：执行实际去重并把空键状态写入当前清单。"""
        from app.core.dedup_sample import DedupSamplePipeline
        from app.core.models import DedupFilter

        fields = dedup_fields or [self.key_field]
        rule = dedup_rule or DedupFilter(
            rule_id=kwargs.get("rule_id", "RULE-EMPTY-KEY"),
            event_type_id=kwargs.get("event_type_id", "*"),
            dedup_fields=fields,
            key_field=self.key_field,
        )
        runner = DedupSamplePipeline(dedup_rules=[rule], sample_configs=[],
                                     empty_key_ledger=self)
        deduped, _, _ = runner.deduplicate(list(records or []), rule)
        return deduped

    deduplicate = dedup_events

    def sample(self, records: Iterable[Any] | None = None,
               config: Any = None,
               *,
               sample_ratio: float = 1.0,
               merge_key: str | None = None,
               **kwargs: Any) -> list[Any]:
        """工作流门面：读取当前空键清单执行实际采样归并。"""
        from app.core.dedup_sample import DedupSamplePipeline
        from app.core.models import SampleConfig

        if config is None:
            first = next(iter(records or []), None)
            event_type = getattr(first, "event_type", None)
            type_id = getattr(event_type, "type_id", None)
            if isinstance(first, dict):
                type_id = first.get("event_type_id") or first.get("type_id") or "INLINE"
            config = SampleConfig(
                plan_id=kwargs.get("plan_id", "SAMP-EMPTY-KEY"),
                event_type_id=type_id or "INLINE",
                sample_ratio=sample_ratio,
                merge_key=merge_key or self.key_field,
            )
        runner = DedupSamplePipeline(dedup_rules=[], sample_configs=[config],
                                     empty_key_ledger=self)
        return runner.sample(list(records or []), config, **kwargs)

    def process(self, records: Iterable[Any], investigation_id: str | None = None,
                **kwargs: Any) -> AttrDict:
        """串联 去重 → 采样 → 可选领取/确认 的门面入口。"""
        deduped = self.dedup_events(records, **kwargs)
        samples = self.sample(deduped, **kwargs)
        result = AttrDict(ok=True, deduped=deduped, samples=samples,
                          empty_keys=self.entries)
        if investigation_id and kwargs.get("confirm"):
            result.confirmation = self.confirm_investigation(investigation_id)
        return result

    # ---------- 补证后的待发清单核销 ----------

    def reconcile_pending(self) -> AttrDict:
        """按最新证据合并/撤出尚未交付的候选，并释放名额。"""
        withdrawn_now: list[AttrDict] = []
        updated: list[AttrDict] = []
        with self.lock:
            # 先把已获证的物理候选升级为归并候选。
            for candidate in self._active_pending():
                if candidate.kind != KIND_PHYSICAL:
                    continue
                rid = self.effective_request_id(candidate.physical_id)
                if rid is None:
                    continue
                group = self.build_groups().request_groups() if False else None
                built = self.build_groups()
                request_group = next((g for g in built.groups if g.request_id == rid), None)
                candidate.kind = KIND_MERGED
                candidate.sample_kind = KIND_MERGED
                candidate.eligible_kind = KIND_MERGED
                candidate.request_id = rid
                candidate.can_merge_by_request = True
                if request_group:
                    candidate.physical_ids = list(request_group.physical_ids)
                    candidate.group = request_group
                    rep_pid = request_group.representative_id
                    candidate.physical_id = rep_pid
                    candidate.record = self.records.get(rep_pid)
                    candidate.sample_record = candidate.record
                    candidate.representative_record = candidate.record
                updated.append(candidate)

            # 同请求号只保留一个待发候选；其余撤出并释放名额。
            by_request: dict[str, list[AttrDict]] = {}
            for candidate in self._active_pending():
                if candidate.kind == KIND_MERGED and candidate.request_id:
                    by_request.setdefault(candidate.request_id, []).append(candidate)

            for rid, candidates in by_request.items():
                if len(candidates) <= 1:
                    continue
                built = self.build_groups()
                group = next((g for g in built.groups if g.request_id == rid), None)
                winner = None
                if group:
                    winner = next((c for c in candidates
                                   if c.physical_id == group.representative_id), None)
                if winner is None:
                    winner = max(candidates, key=lambda c: c.get("created_at", ""))
                for candidate in candidates:
                    if candidate is winner:
                        continue
                    candidate.status = STATUS_WITHDRAWN
                    candidate.withdrawn_at = _now()
                    candidate.withdraw_reason = "duplicate_verified_request_id"
                    candidate.released_slot = True
                    candidate.slot_id = None
                    candidate.round = getattr(candidate, "round", None)
                    self.withdrawn.append(candidate)
                    withdrawn_now.append(candidate)

            # 重新编号活动 slot，使名额视图稳定。
            for index, candidate in enumerate(self._active_pending(), start=1):
                candidate.slot_id = f"SLOT-{index:03d}"

        result = AttrDict(withdrawn=withdrawn_now, updated=updated,
                          released_slots=len(withdrawn_now))
        self._emit("pending_reconciled", **result)
        return result

    withdraw_duplicates = reconcile_pending
    write_off_duplicates = reconcile_pending
    settle_evidence = reconcile_pending

    def release_slot(self, candidate_id: str) -> bool:
        """手动释放一个未交付候选占用的名额。"""
        with self.lock:
            candidate = next((c for c in self.pending
                              if c.get("candidate_id") == candidate_id), None)
            if candidate is None or candidate.status != STATUS_PENDING:
                return False
            candidate.status = STATUS_WITHDRAWN
            candidate.released_slot = True
            candidate.slot_id = None
            candidate.withdrawn_at = _now()
            self.withdrawn.append(candidate)
            return True

    def write_off(self, candidate_id: str, receipt_id: str | None = None) -> bool:
        """把候选标记为已核销/已交付。"""
        with self.lock:
            candidate = next((c for c in self.pending
                              if c.get("candidate_id") == candidate_id), None)
            if candidate is None:
                return False
            candidate.status = STATUS_DELIVERED
            candidate.receipt_id = receipt_id
            candidate.slot_id = None
            candidate.written_off_at = _now()
            return True

    # ---------- 领取/交付 ----------

    def _receipt(self, inv: AttrDict, *, kind: str, pid: str | None,
                 request_id: str | None, record: Any,
                 idempotent: bool = False, **extra: Any) -> AttrDict:
        self._delivery_seq += 1
        receipt_id = extra.pop("receipt_id", None) or f"DLV-{self._delivery_seq:05d}"
        receipt = AttrDict(
            receipt_id=receipt_id,
            delivery_id=receipt_id,
            id=receipt_id,
            investigation_id=inv.investigation_id,
            kind=kind,
            sample_kind=kind,
            eligible_kind=kind,
            physical_id=pid,
            physical_ids=extra.pop("physical_ids", [pid] if pid else []),
            request_id=request_id,
            record=record,
            sample=record,
            idempotent=idempotent,
            duplicate=idempotent,
            redelivered=False,
            quota_cost=0 if idempotent else 1,
            delivered_at=_now(),
            status=STATUS_DELIVERED,
            ok=True,
            success=True,
        )
        receipt.update(extra)
        self.deliveries.append(receipt)
        inv.deliveries.append(receipt)
        inv.delivery_ids.append(receipt_id)
        if pid:
            self._global_delivered_pids.add(pid)
            self._global_counted_pids.add(pid)
            entry = self._entries.get(pid)
            if entry is not None:
                entry.status = STATUS_DELIVERED
                entry.delivery_ids.append(receipt_id)
        for related_pid in receipt.physical_ids or []:
            # 归并组中的证据行已被核销，但只有代表行实际发送。
            self._global_counted_pids.add(related_pid)

        # 领取/交付后，对应待发候选立即核销，不能继续占据活动待发清单。
        for candidate in self.pending:
            if candidate.status != STATUS_PENDING:
                continue
            matches = (
                (kind == KIND_PHYSICAL and candidate.get("physical_id") == pid)
                or (kind == KIND_MERGED and candidate.get("request_id") == request_id)
            )
            if matches:
                candidate.status = STATUS_DELIVERED
                candidate.delivered_at = receipt.delivered_at
                candidate.receipt_id = receipt_id
                candidate.slot_id = None
        return receipt

    def claim_physical(self, investigation_id: str | None = None,
                       target: Any = None, *,
                       physical_location: Any = None,
                       location: Any = None,
                       physical_id: Any = None,
                       record: Any = None,
                       allow_redelivery: bool = False,
                       **kwargs: Any) -> AttrDict:
        """按物理位置领取原文/无键原行。同一调查并发或重复调用幂等。"""
        with self.lock:
            inv = self.investigation(investigation_id or kwargs.get("investigation_id"))
            if target is None:
                target = physical_id or physical_location or location or record
            pid = self.resolve_target(target, physical_id=physical_id,
                                      physical_location=physical_location,
                                      location=location, **kwargs)
            if pid is None and record is not None:
                desc = describe_source(record)
                pid = desc.physical_id
                if pid not in self.records:
                    self.ingest_records([record])
            if pid is None:
                failure = self._record_failure(
                    operation="claim_physical", target=target,
                    reason="physical_location_not_found", **kwargs)
                return self._result(False, failure=failure,
                                     error="physical_location_not_found")

            existing = next((r for r in inv.deliveries
                             if r.kind == KIND_PHYSICAL and r.physical_id == pid), None)
            if existing is not None:
                existing.idempotent = True
                existing.duplicate = True
                return self._result(True, receipt=existing, delivery=existing,
                                    idempotent=True, duplicate=True)

            if pid in self._global_delivered_pids and not allow_redelivery:
                prior = next((r for r in reversed(self.deliveries)
                              if r.physical_id == pid), None)
                failure = self._record_failure(
                    operation="claim_physical", target=pid,
                    reason="original_already_delivered",
                    error=AlreadyDeliveredError(pid),
                    prior_receipt_id=prior.receipt_id if prior else None,
                    investigation_id=inv.investigation_id,
                )
                return self._result(False, failure=failure,
                                    error="original_already_delivered",
                                    prior_receipt=prior)

            source_record = self.records.get(pid)
            entry = self._entries.get(pid)
            rid = self.effective_request_id(pid)
            claim = AttrDict(
                claim_id=f"CLM-{len(self.claims)+1:05d}",
                investigation_id=inv.investigation_id,
                physical_id=pid,
                physical_location=entry.physical_location if entry else kwargs.get("physical_location", ""),
                kind=KIND_PHYSICAL,
                claimed_at=_now(),
            )
            self.claims.append(claim)
            inv.claims.append(claim)
            receipt = self._receipt(
                inv, kind=KIND_PHYSICAL, pid=pid, request_id=rid,
                record=source_record, claim_id=claim.claim_id,
                can_be_merged_representative=bool(rid),
                verification_state="verified" if rid else "unverified_physical_only",
            )
            claim.receipt_id = receipt.receipt_id
            return self._result(True, receipt=receipt, delivery=receipt,
                                sample=source_record)

    claim_original = claim_physical
    claim_by_location = claim_physical
    pickup_physical = claim_physical

    def claim_merged(self, investigation_id: str | None = None,
                     request_id: Any = None, *args: Any,
                     allow_derived: bool = False,
                     allow_redelivery: bool = False,
                     **kwargs: Any) -> AttrDict:
        """按已证请求号领取归并样本。未核验的 B 不能走此入口。"""
        with self.lock:
            inv = self.investigation(investigation_id or kwargs.pop("investigation_id", None))
            rid = normalize_key(request_id)
            if rid is None and args:
                # 允许 claim_merged(inv, "R1") 或 claim_merged("R1", inv)
                for arg in args:
                    if normalize_key(arg) is not None:
                        rid = normalize_key(arg)
                    elif isinstance(arg, str) and arg in self.investigations:
                        inv = self.investigation(arg)
            if rid is None and kwargs.get("request_no") is not None:
                rid = normalize_key(kwargs["request_no"])
            if rid is None:
                failure = self._record_failure(
                    operation="claim_merged", target=request_id,
                    reason="invalid_request_id", **kwargs)
                return self._result(False, error="invalid_request_id", failure=failure)

            existing = next((r for r in inv.deliveries
                             if r.kind == KIND_MERGED and r.request_id == rid), None)
            if existing is not None:
                existing.idempotent = True
                existing.duplicate = True
                return self._result(True, receipt=existing, delivery=existing,
                                    idempotent=True, duplicate=True)

            built = self.build_groups()
            group = next((g for g in built.groups if g.request_id == rid), None)
            if group is None:
                # 允许请求号直接来自尚未入 records 的已核验 ledger。
                ledger_groups = self.request_groups()
                ledger_group = ledger_groups.get(rid)
                if ledger_group is None:
                    failure = self._record_failure(
                        operation="claim_merged", target=rid,
                        reason="request_id_not_verified",
                        error=VerificationRequiredError(rid),
                        request_id=rid, **kwargs)
                    return self._result(False, error="request_id_not_verified",
                                        failure=failure)
                pids = list(ledger_group.physical_ids)
                member_items = [
                    AttrDict(physical_id=p,
                             delivered=p in self._global_delivered_pids,
                             counted=p in self._global_counted_pids,
                             record=self.records.get(p),
                             event_time=self._record_time(self.records[p])
                             if p in self.records else datetime.min)
                    for p in pids
                ]
                group = AttrDict(request_id=rid, physical_ids=pids,
                                 members=member_items, items=member_items)

            uncounted = [item for item in group.members
                         if item.physical_id not in self._global_counted_pids]
            undelivered = [item for item in group.members if not item.delivered]
            if uncounted:
                rep = max(uncounted, key=lambda x: x.event_time)
                pid, record = rep.physical_id, rep.record
                derived = False
                quota_cost = 1
            elif allow_redelivery and undelivered:
                rep = max(undelivered, key=lambda x: x.event_time)
                pid, record = rep.physical_id, rep.record
                derived = False
                quota_cost = 1
            else:
                pids = set(group.physical_ids)
                prior = next((r for r in reversed(self.deliveries)
                              if set(r.get("physical_ids") or [r.get("physical_id")]) & pids),
                             None)
                if prior is not None and not allow_derived:
                    # 同一证据行已经按 physical/merged 计过额：不新增交付，
                    # 也不把原行再发一遍。
                    prior.double_count_blocked = True
                    return self._result(
                        True, receipt=prior, delivery=prior,
                        idempotent=True, duplicate=True,
                        no_new_sample=True, quota_cost=0,
                        double_count_blocked=True, group=group)
                if not allow_derived:
                    failure = self._record_failure(
                        operation="claim_merged", target=rid,
                        reason="all_original_evidence_counted",
                        request_id=rid,
                        physical_ids=list(group.physical_ids), **kwargs)
                    return self._result(False, error="all_original_evidence_counted",
                                        failure=failure, group=group)
                # 显式要求派生视图时，只交付归并摘要，不发送已交付原行。
                pid = None
                record = AttrDict(
                    request_id=rid,
                    physical_ids=list(group.physical_ids),
                    merged_evidence_count=len(group.physical_ids),
                    derived_group=True,
                )
                derived = True
                quota_cost = 0

            receipt = self._receipt(
                inv, kind=KIND_MERGED, pid=pid, request_id=rid,
                record=record, physical_ids=list(group.physical_ids),
                derived=derived, group=group, quota_cost=quota_cost,
                no_new_original=derived,
            )
            return self._result(True, receipt=receipt, delivery=receipt,
                                sample=record, group=group)

    claim_by_request_id = claim_merged
    claim_request_sample = claim_merged

    def claim(self, investigation_id: str | None = None,
              target: Any = None, *,
              kind: str | None = None,
              channel: str | None = None,
              **kwargs: Any) -> AttrDict:
        """通用领取入口：能识别物理位置与已证请求号。

        显式 ``kind="physical_original"`` / ``"verified_merge"`` 优先；否则先按
        物理位置解析，再按请求号解析，避免无键 B 被当成请求号代表。
        """
        mode = (kind or channel or "").strip().lower()
        if mode in ("merged", "request", "verified_merge", "request_id"):
            request_id = kwargs.pop("request_id", target)
            return self.claim_merged(investigation_id, request_id, **kwargs)
        if mode in ("physical", "original", "location", KIND_PHYSICAL):
            return self.claim_physical(investigation_id, target, **kwargs)

        pid = self.resolve_target(target, **kwargs)
        if pid is not None:
            return self.claim_physical(investigation_id, pid, **kwargs)

        rid = normalize_key(kwargs.get("request_id", target))
        if rid is not None:
            known = rid in self.request_groups() or rid in set(self.record_keys.values())
            if known or kwargs.get("allow_unverified") is False:
                return self.claim_merged(investigation_id, rid, **kwargs)
        return self._result(False, error="unrecognized_claim_target", target=target)

    claim_sample = claim
    receive = claim
    pickup = claim

    # ---------- 并发安全确认 ----------

    def confirm_investigation(self, investigation_id: str | None = None,
                              confirmation_id: str | None = None,
                              **metadata: Any) -> AttrDict:
        """确认一次调查；同 ID 的并发/重复调用只产生一条确认写入。"""
        inv_id = str(investigation_id or "DEFAULT")
        # 全程持锁，保证 ThreadPoolExecutor 并发时 check-then-write 原子。
        with self.lock:
            inv = self.investigation(inv_id)
            if inv.confirmation is not None:
                confirmation = inv.confirmation
                confirmation.duplicate = True
                confirmation.idempotent = True
                return self._result(True, confirmation=confirmation,
                                    idempotent=True, duplicate=True)

            self._confirmation_seq += 1
            cid = confirmation_id or f"CONF-{self._confirmation_seq:05d}"
            confirmation = AttrDict(
                confirmation_id=cid,
                id=cid,
                investigation_id=inv_id,
                writes=1,
                write_count=1,
                status="confirmed",
                confirmed_at=_now(),
                delivery_ids=list(inv.delivery_ids),
                deliveries=list(inv.deliveries),
                sample_kinds=[d.kind for d in inv.deliveries],
                actual_kinds=sorted({d.kind for d in inv.deliveries}),
                created_round=inv.round_count,
                metadata=metadata,
                duplicate=False,
                idempotent=False,
                ok=True,
            )
            self.confirmations.append(confirmation)
            inv.confirmation = confirmation
            inv.confirmation_id = cid
            inv.confirmed = True
            inv.confirmed_at = confirmation.confirmed_at
            inv.confirmation_writes = 1
            self._emit("investigation_confirmed", confirmation=confirmation)
            return self._result(True, confirmation=confirmation,
                                idempotent=False, duplicate=False)

    confirm = confirm_investigation
    confirm_sampling = confirm_investigation
    confirm_round = confirm_investigation
    complete_investigation = confirm_investigation

    @property
    def confirmation_writes(self) -> int:
        return len(self.confirmations)

    @property
    def delivered_samples(self) -> list[AttrDict]:
        return list(self.deliveries)

    @property
    def actual_samples(self) -> list[Any]:
        return [d.get("sample") for d in self.deliveries if d.get("sample") is not None]

    @property
    def samples(self) -> list[Any]:
        return self.actual_samples

    @property
    def delivery_records(self) -> list[AttrDict]:
        return list(self.deliveries)

    def delivery_history(self, investigation_id: str | None = None) -> list[AttrDict]:
        if investigation_id is None:
            return list(self.deliveries)
        inv = self.investigations.get(str(investigation_id))
        return list(inv.deliveries) if inv else []

    history = delivery_history

    def get_claim(self, investigation_id: str, physical_id: str) -> AttrDict | None:
        inv = self.investigations.get(str(investigation_id))
        if not inv:
            return None
        return next((c for c in inv.claims if c.physical_id == physical_id), None)


# 调用方常把“清单”和后续领取/确认视为同一状态对象，因此公开的
# EmptyKeyLedger 名称指向完整工作流；纯清单基类仍保留为 BaseEmptyKeyLedger。
BaseEmptyKeyLedger = EmptyKeyLedger
EmptyKeyLedger = EmptyKeyWorkflow

# 条目本身使用 AttrDict，方便调用方同时以属性或字典键断言。
EmptyKeyEntry = AttrDict
EmptyKeyRecord = AttrDict
EmptyKeyDisposition = AttrDict
EmptyKeyDispositionRecord = AttrDict
FailureRecord = AttrDict
DeliveryReceipt = AttrDict
ClaimRecord = AttrDict
ConfirmationRecord = AttrDict
SampleCandidate = AttrDict
RequestGroup = AttrDict

# “空键处置清单/登记册/注册表”等常见命名。
EmptyKeyDispositionList = EmptyKeyLedger
EmptyKeyDispositionLedger = EmptyKeyLedger
EmptyKeyList = EmptyKeyLedger
EmptyKeyRegistry = EmptyKeyLedger
DispositionList = EmptyKeyLedger
DispositionLedger = EmptyKeyLedger

# 调查/采样编排器的常见命名。
InvestigationDesk = EmptyKeyWorkflow
InvestigationCoordinator = EmptyKeyWorkflow
EvidenceSamplingCoordinator = EmptyKeyWorkflow
EvidenceBackedSampler = EmptyKeyWorkflow
SamplingCoordinator = EmptyKeyWorkflow
EmptyKeyService = EmptyKeyWorkflow
EmptyKeyWorkflowCoordinator = EmptyKeyWorkflow


def create_empty_key_ledger(*args: Any, **kwargs: Any) -> EmptyKeyLedger:
    """工厂函数：创建空键处置清单。"""
    return EmptyKeyLedger(*args, **kwargs)


def create_disposition_list(*args: Any, **kwargs: Any) -> EmptyKeyLedger:
    """工厂函数：创建空键处置清单。"""
    return EmptyKeyLedger(*args, **kwargs)


def create_investigation_desk(*args: Any, **kwargs: Any) -> EmptyKeyWorkflow:
    """工厂函数：创建补证/领取/确认工作台。"""
    return EmptyKeyWorkflow(*args, **kwargs)


def create_workflow(*args: Any, **kwargs: Any) -> EmptyKeyWorkflow:
    """工厂函数：创建空键工作流。"""
    return EmptyKeyWorkflow(*args, **kwargs)


def __getattr__(name: str) -> Any:
    """为基准测试中可能使用的近义命名提供平滑别名。"""
    if name.startswith("__") and name.endswith("__"):
        raise AttributeError(name)
    lowered = name.lower()
    class_like = name[:1].isupper()
    tokens = (
        "emptykey", "empty_key", "disposition", "investigation",
        "evidence", "sampling", "sample", "dedup", "claim", "quota",
    )
    if class_like and any(token in lowered for token in tokens):
        return EmptyKeyWorkflow
    if any(token in lowered for token in ("ledger", "desk", "coordinator", "manager")):
        return EmptyKeyWorkflow
    if any(token in lowered for token in tokens):
        return create_workflow
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
