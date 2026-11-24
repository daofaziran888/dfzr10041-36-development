"""拾音工坊核心数据模型：真实日志采集与事件流处理的数据结构。"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LogFormat(Enum):
    """日志格式枚举，对应 parser_rule 的正则表达式匹配。"""
    ACCESS = "access"
    APP = "app"
    SYS = "sys"
    CUSTOM = "custom"


class ParseResultStatus(Enum):
    """解析结果状态。"""
    OK = "ok"
    FORMAT_MISMATCH = "format_mismatch"
    FIELD_MISSING = "field_missing"
    ENCODING_ERROR = "encoding_error"
    LINE_EMPTY = "line_empty"


class MaskMethod(Enum):
    """脱敏方式枚举。"""
    PHONE = "phone"
    ID_CARD = "id_card"
    EMAIL = "email"
    IP = "ip"
    TOKEN = "token"
    CUSTOM_REGEX = "custom_regex"


@dataclass
class LogSourceConfig:
    """日志来源配置模型——对应 log_source 模块。"""
    source_id: str
    source_name: str
    app_label: str
    log_path: str
    log_format: str
    encoding: str = "utf-8"
    collect_method: str = "file_tail"
    access_state: str = "待验证"

    def match_format(self, line: str) -> bool:
        """校验一条日志行是否匹配此来源的格式。"""
        if self.log_format == "access":
            return bool(re.match(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s.*?"[A-Z]+\s\S+\sHTTP',
                line.strip()))
        if self.log_format == "app":
            return bool(re.match(
                r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}\s+\[.*?\]\s+(INFO|WARN|ERROR|DEBUG)\s+',
                line.strip()))
        if self.log_format == "sys":
            return bool(re.match(
                r'^[\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[\w-]+\s+[\w-]+\[',
                line.strip()))
        return bool(line.strip() and len(line.strip()) > 10)


@dataclass
class ParseRule:
    """解析规则模型——对应 parser_rule 模块。"""
    rule_id: str
    source_id: str
    regex_pattern: str
    field_names: list[str]
    time_format: str = "%Y-%m-%d %H:%M:%S"
    multiline: bool = False
    priority: int = 0
    state: str = "草稿"
    _compiled_re: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern[str]:
        """编译正则表达式（惰性编译）。"""
        if self._compiled_re is None:
            self._compiled_re = re.compile(self.regex_pattern)
        return self._compiled_re

    def parse(self, line: str) -> tuple[ParseResultStatus, dict[str, str] | None]:
        """用解析规则提取一条日志行的字段。"""
        try:
            compiled = self.compile()
            m = compiled.match(line.strip())
            if m is None:
                return ParseResultStatus.FORMAT_MISMATCH, None
            fields = dict(zip(self.field_names, m.groups()))
            missing = [name for name in self.field_names if name not in fields]
            if missing:
                return ParseResultStatus.FIELD_MISSING, fields
            return ParseResultStatus.OK, fields
        except re.error:
            return ParseResultStatus.FORMAT_MISMATCH, None


@dataclass
class LogEntry:
    """单条日志条目——跨模块流转的核心数据载体。"""
    raw_line: str
    line_number: int
    source_id: str
    parsed_fields: dict[str, str] | None = None
    parse_status: ParseResultStatus = ParseResultStatus.OK
    event_time: datetime | None = None
    host: str = ""
    checksum: str = field(default="")

    def compute_checksum(self) -> str:
        """基于原始行和解析字段计算内容校验哈希。"""
        raw = (
            f"{self.source_id}|{self.line_number}|{self.raw_line[:200]}"
            f"|{sorted((self.parsed_fields or {}).items())}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def __post_init__(self):
        if not self.checksum:
            self.checksum = self.compute_checksum()


@dataclass
class MaskRule:
    """脱敏规则模型——对应 mask_rule 模块。"""
    rule_id: str
    target_field: str
    mask_method: MaskMethod
    mask_pattern: str
    retain_count: int = 0
    rule_state: str = "草稿"

    def apply(self, value: str) -> str:
        """对字段值执行脱敏变换。"""
        if not value:
            return value
        if self.mask_method == MaskMethod.PHONE:
            if len(value) >= 11:
                return value[:3] + "****" + value[-4:]
            return value[:1] + "****" + value[-1:] if len(value) > 2 else "****"
        if self.mask_method == MaskMethod.ID_CARD:
            if len(value) >= 18:
                return value[:6] + "********" + value[-4:]
            return value[:2] + "****" + value[-2:] if len(value) > 4 else "****"
        if self.mask_method == MaskMethod.EMAIL:
            parts = value.split("@")
            if len(parts) == 2:
                local = parts[0]
                masked_local = local[:2] + "***" + local[-1:] if len(local) > 3 else "***"
                return f"{masked_local}@{parts[1]}"
            return "***@***"
        if self.mask_method == MaskMethod.IP:
            octets = value.split(".")
            if len(octets) == 4:
                return f"{octets[0]}.{octets[1]}.*.*"
            return "***.***.***.***"
        if self.mask_method == MaskMethod.CUSTOM_REGEX:
            compiled = re.compile(self.mask_pattern)
            return compiled.sub("***", value)
        return value


@dataclass
class MaskResult:
    """脱敏变换结果——记录哪个字段被何种方式脱敏。"""
    rule_id: str
    field_name: str
    original: str
    masked: str
    method: MaskMethod
    is_masked: bool = True

    def verify(self) -> bool:
        """校验脱敏结果：敏感原值不应出现在掩码后的结果中。"""
        if not self.is_masked:
            return True
        if len(self.original) < 3:
            return self.masked != self.original
        core = self.original[3:-3] if len(self.original) > 6 else self.original
        return core not in self.masked


@dataclass
class FieldEnrichRule:
    """字段增强规则——对应 field_enrich 模块。"""
    rule_id: str
    target_field: str
    enrich_source: str
    mapping_dict: dict[str, str]
    default_value: str = "unknown"
    priority: int = 0

    def enrich(self, fields: dict[str, str]) -> str:
        """根据映射字典增强目标字段。"""
        key = fields.get(self.enrich_source, "").strip()
        return self.mapping_dict.get(key, self.default_value)


@dataclass
class EventTypeDef:
    """事件类型定义——对应 event_type 模块。"""
    type_id: str
    type_name: str
    category_tag: str
    severity: str = "INFO"
    alert_threshold: int = 0
    sample_ratio: float = 1.0
    retain_days: int = 30


@dataclass
class EventRecord:
    """标准化事件记录——解析、脱敏、增强后的最终产物。"""
    record_id: str
    event_type: EventTypeDef
    original_content: str
    parsed_fields: dict[str, str]
    masked_fields: dict[str, str]
    enriched_fields: dict[str, str]
    event_time: datetime
    source_host: str
    store_partition: str = ""
    index_state: str = "已写入"
    source_id: str = ""
    source: str = ""
    source_path: str = ""
    file_path: str = ""
    physical_location: str = ""
    source_location: str = ""
    location: str = ""
    position: str = ""
    locator: str = ""
    physical_ref: str = ""
    line_number: int | None = None
    line_no: int | None = None


@dataclass
class DedupFilter:
    """去重过滤规则——对应 dedup_filter 模块。"""
    rule_id: str
    event_type_id: str
    dedup_fields: list[str]
    window_minutes: int = 60
    fingerprint_algo: str = "sha256"
    hit_count: int = 0
    ignore_count: int = 0
    key_field: str | None = None

    def fingerprint(self, event: EventRecord) -> str:
        """基于去重字段生成事件指纹。

        合法的 ``0``/``"0"`` 不会被 truthy 判断吞掉；请求号类字段缺失或为空时，
        指纹会绑定真实物理位置，避免把不同的无键原行错误归为同一指纹组。
        """
        from app.core.empty_key import (
            REQUEST_KEY_FIELDS, classify_key, describe_source, normalize_key,
        )

        if isinstance(event, dict):
            event_type = event.get("event_type")
            if hasattr(event_type, "type_id"):
                type_id = event_type.type_id
            else:
                type_id = event.get("event_type_id") or event.get("type_id") or "dict-event"
            parsed_fields = event.get("parsed_fields")
            if not isinstance(parsed_fields, dict):
                parsed_fields = event.get("fields") if isinstance(event.get("fields"), dict) else event
            masked_fields = event.get("masked_fields") if isinstance(
                event.get("masked_fields"), dict) else {}
        else:
            type_id = event.event_type.type_id
            parsed_fields = event.parsed_fields
            masked_fields = event.masked_fields

        key_parts = [type_id]
        has_empty_request_key = False
        for field in sorted(self.dedup_fields):
            raw: Any = None
            found = False
            for container in (parsed_fields, masked_fields):
                if isinstance(container, dict) and field in container:
                    raw = container.get(field)
                    found = True
                    break
            if not found and not isinstance(event, dict):
                raw = getattr(event, field, None)
                if raw is not None:
                    found = True
            state = classify_key(raw if found else None)
            if state == "valid":
                val = normalize_key(raw)
                marker = val
            else:
                # 显式区分缺失、空串和纯空白，不再都序列化成 field=。
                marker = f"<{state.upper()}>"
                if field in REQUEST_KEY_FIELDS or len(self.dedup_fields) == 1:
                    has_empty_request_key = True
            key_parts.append(f"{field}={marker}")

        if has_empty_request_key:
            desc = describe_source(event)
            key_parts.extend([
                f"physical_id={desc.physical_id}",
                f"source={desc.source_id}",
                f"location={desc.location}",
            ])

        raw_key = "|".join(key_parts)
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def key_state(self, event: EventRecord, key_field: str | None = None) -> str:
        """返回去重业务键状态；单字段规则默认检查该字段。"""
        from app.core.empty_key import classify_key, extract_key

        field = key_field or (self.dedup_fields[0] if len(self.dedup_fields) == 1 else "request_id")
        _, raw, _ = extract_key(event, field)
        return classify_key(raw)

    def is_duplicate(self, event: EventRecord, seen_fingerprints: set[str]) -> bool:
        """判断事件是否重复。"""
        fp = self.fingerprint(event)
        if fp in seen_fingerprints:
            self.hit_count += 1
            return True
        seen_fingerprints.add(fp)
        return False


@dataclass
class SampleConfig:
    """采样归并配置——对应 sample_job 模块。"""
    plan_id: str
    event_type_id: str
    sample_ratio: float
    merge_key: str = ""
    merge_window_minutes: int = 5
    retain_policy: str = "latest"


@dataclass
class BatchCheckpoint:
    """批次检查点——对应 batch_checkpoint 模块。"""
    checkpoint_id: str
    job_id: str
    file_path: str
    byte_offset: int
    line_count: int
    content_hash: str
    check_time: datetime = field(default_factory=datetime.now)
    state: str = "已记录"


@dataclass
class IngestJob:
    """采集作业模型——对应 ingest_job 模块。"""
    job_id: str
    source_id: str
    collect_mode: str = "incremental"
    file_cursor: int = 0
    batch_size: int = 100
    thread_count: int = 1
    processed_lines: int = 0
    skipped_lines: int = 0
    state: str = "待执行"


@dataclass
class IngestMetric:
    """采集指标——对应 ingest_metric 模块。"""
    metric_id: str
    source_id: str
    ingest_rate: float = 0.0
    process_delay_ms: float = 0.0
    error_rate: float = 0.0
    backlog_lines: int = 0
    sample_time: datetime = field(default_factory=datetime.now)


@dataclass
class QualityReport:
    """质量报告——对应 quality_report 模块。"""
    report_id: str
    source_id: str
    completeness_rate: float = 0.0
    parse_success_rate: float = 0.0
    field_coverage_rate: float = 0.0
    time_delay_seconds: float = 0.0
    eval_period: str = "daily"
    state: str = "待生成"


@dataclass
class AnomalyRule:
    """异常告警规则——对应 anomaly_rule 模块。"""
    rule_id: str
    event_type_id: str
    detect_condition: str
    alert_level: str = "WARNING"
    trigger_frequency: int = 1
    aggregate_window_minutes: int = 5
    notify_channel: str = "webhook"


@dataclass
class ForwardRule:
    """转发路由规则——对应 forward_rule 模块。"""
    rule_id: str
    event_type_id: str
    target_address: str
    forward_format: str = "json"
    batch_size: int = 100
    retry_limit: int = 3
    timeout_seconds: int = 30