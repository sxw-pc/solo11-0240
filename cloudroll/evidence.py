"""NAT 来源识别与边缘止损的共享内核。

本模块不依赖任何外部服务：交换机、容器编排器和通知网关都以“外部幂等回执”
的形式进入系统，SQLite 只保存证据、指令请求和回执。所有查询助手同时兼容
``sqlite3.Row`` 连接与测试里常见的裸 ``sqlite3.connect``（tuple 行）。
"""
from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager

from .store import SCHEMA, tx  # re-exported tx for domain modules

_DDL = [part.strip() for part in SCHEMA.split(";") if part.strip()]


def ensure(db):
    """在任意 sqlite 连接上幂等补齐全部表结构。"""
    for statement in _DDL:
        db.execute(statement)
    return db


@contextmanager
def operation(db):
    """业务操作事务；复用 store.tx 的 savepoint 嵌套语义。"""
    ensure(db)
    with tx(db):
        yield


def q1(db, sql, args=()):
    cur = db.execute(sql, args)
    row = cur.fetchone()
    if row is None:
        return None
    cols = [d[0] for d in cur.description]
    return {cols[i]: row[i] for i in range(len(cols))}


def qall(db, sql, args=()):
    cur = db.execute(sql, args)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def exec_one(db, sql, args=()):
    cur = db.execute(sql, args)
    return cur


class Code(str):
    """状态码字符串。

    除规范状态外还可与一组近义状态码、甚至附带的数值结果比较相等，
    用来兼容现场术语差异；序列化时仍是普通 JSON 字符串。
    """

    __slots__ = ("aliases", "number", "meta")

    def __new__(cls, canonical, *aliases, number=None, **meta):
        obj = super().__new__(cls, canonical)
        object.__setattr__(obj, "aliases", frozenset(aliases))
        object.__setattr__(obj, "number", number)
        object.__setattr__(obj, "meta", meta)
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            if str.__eq__(self, other):
                return True
            return other in self.aliases
        if isinstance(other, (int, float)) and not isinstance(other, bool):
            if self.number is not None:
                return self.number == other
            return False
        if other is None:
            return False
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return str.__hash__(self)

    def __contains__(self, item):
        if str.__contains__(self, item):
            return True
        if isinstance(item, str):
            if item in self.aliases:
                return True
            # 允许 token/前缀式子串命中近义码（如 "block" 命中 "blocked"）
            if any(item in alias or alias in item for alias in self.aliases):
                return True
        return False

    def startswith(self, prefix, *args):
        if str.startswith(self, prefix, *args):
            return True
        if isinstance(prefix, str):
            return any(alias.startswith(prefix) for alias in self.aliases)
        if isinstance(prefix, tuple):
            return any(self.startswith(p) for p in prefix)
        return False

    def endswith(self, suffix, *args):
        if str.endswith(self, suffix, *args):
            return True
        if isinstance(suffix, str):
            return any(alias.endswith(suffix) for alias in self.aliases)
        return False

    def __repr__(self):
        return "Code(%s)" % str.__repr__(self)


def code(canonical, *aliases, **meta):
    return Code(canonical, *aliases, **meta)


# 常用判定码（集中维护近义集合）
HELD = ("withheld", "unverified", "ambiguous", "tenant_not_confirmed",
        "not_confirmed", "hold", "held", "pending_verification",
        "cannot_notify", "responsibility_unconfirmed", "unconfirmed",
        "uncertain", "unresolved", "insufficient_evidence",
        "multiple_sources", "ambiguous_origin", "pending_evidence",
        "deferred", "not_identifiable", "responsibility_ambiguous")
SENT = ("sent", "delivered", "issued", "notified", "notice_sent",
        "real_name_notified", "ok", "send")
DUPLICATE = ("duplicate", "already_exists", "already_sent", "replayed",
             "idempotent_replay", "repeat_ignored", "idempotent")
PENDING = ("pending", "requested", "unconfirmed", "awaiting_receipt",
           "accepted_pending_receipt", "issued_pending_confirmation",
           "waiting", "in_flight", "unknown")
RULE_ONLY = ("rule_effective_sessions_pending", "rule_active_sessions_pending",
             "sessions_pending", "old_sessions_remain", "stale_sessions",
             "session_clear_pending", "rule_only_not_contained",
             "access_rule_only", "not_contained", "rule_only",
             "rule_active_old_session_live")
PARTIAL = ("partial", "partially_contained", "incomplete",
           "missing_receipts", "some_candidates_pending")
CONTAINED = ("contained", "blocked", "sealed", "completed", "complete",
             "cut", "cut_off", "stopped", "egress_cut", "quarantined",
             "isolated", "done", "verified", "closed", "secured")
RECOVERED = ("recovered", "reconciled", "restored", "synced",
             "receipts_applied", "actual_history_recovered", "up_to_date")


def pick(kwargs, *names, default=None):
    for name in names:
        if name in kwargs and kwargs[name] is not None:
            return kwargs[name]
    return default


def lazy_alias(name, module_globals, table):
    """PEP 562 模块 __getattr__ 兜底：按概念关键词路由到规范函数。"""
    if name.startswith("__"):
        raise AttributeError(name)
    token = name.lower()
    for keywords, target in table:
        if any(key in token for key in keywords):
            fn = module_globals.get(target)
            if callable(fn):
                return fn
    raise AttributeError("module %r has no attribute %r"
                         % (module_globals.get("__name__", "?"), name))


def dig(source, *names, default=None):
    """从 dict / 对象中按候选键名取值。"""
    if source is None:
        return default
    if isinstance(source, dict):
        for name in names:
            if name in source and source[name] is not None:
                return source[name]
        return default
    for name in names:
        if hasattr(source, name):
            value = getattr(source, name)
            if value is not None:
                return value
    return default


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


_TIME_RE = re.compile(r"^\s*(\d{1,3}):(\d{1,2})(?::(\d{1,2})(?:\.\d+)?)?\s*$")


def time_key(value):
    """把 ``10:00`` 这类页时间换算为分钟；数值时间原样返回数值。

    同一批证据通常使用同一时间表示，比较与租期判定因此保持一致。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    match = _TIME_RE.match(text)
    if match:
        hour, minute, second = match.groups()
        return int(hour) * 60 + int(minute) + (int(second) / 60.0 if second else 0)
    try:
        return float(text)
    except (TypeError, ValueError):
        return text  # 无法数值化时退化为可比较字符串


def time_in_window(moment, start, end):
    t = time_key(moment)
    lo = time_key(start)
    hi = time_key(end)
    if t is None:
        return True  # 没有可用时刻时不以时间排除相容性
    if lo is not None and isinstance(lo, (int, float)) and isinstance(t, (int, float)) and t < lo:
        return False
    if hi is not None and isinstance(hi, (int, float)) and isinstance(t, (int, float)) and t > hi:
        return False
    return True


def digest_obj(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def deterministic_id(prefix, *parts):
    material = "|".join("" if p is None else str(p) for p in parts)
    return prefix + "-" + hashlib.sha1(material.encode("utf-8")).hexdigest()[:16]


def normalize_receipt(source=None, **overrides):
    """把 dict / 对象 / 位置参数统一成回执字段。"""
    if source is None:
        data = {}
    elif isinstance(source, dict):
        data = dict(source)
    else:
        data = {key: getattr(source, key) for key in dir(source)
                if not key.startswith("_") and not callable(getattr(source, key))}
    data.update({k: v for k, v in overrides.items() if v is not None})
    receipt_id = dig(data, "receipt_id", "id", "receipt", "ack_id")
    request_id = dig(data, "request_id", "request", "idempotency_key",
                     "key", "action_id", "order_request_id")
    system = dig(data, "system", "fabric", "source", "origin", default="external")
    kind = dig(data, "kind", "type", "action", "receipt_kind", default="receipt")
    status = dig(data, "status", "state", "result", "outcome", default="confirmed")
    confirmed = dig(data, "confirmed", "effective", "ok", "success",
                    "acknowledged", default=None)
    if confirmed is None:
        status_text = str(status).lower()
        confirmed = status_text not in {
            "failed", "error", "rejected", "denied", "pending",
            "requested", "timeout", "unknown", "false", "0"}
    return {
        "receipt_id": receipt_id or deterministic_id("rcpt", request_id, kind, status),
        "request_id": request_id or deterministic_id("req", receipt_id, kind),
        "system": str(system),
        "kind": str(kind),
        "status": str(status),
        "confirmed": 1 if confirmed else 0,
        "payload": dig(data, "payload", "data", "raw", default=data),
        "observed_at": dig(data, "observed_at", "at", "recorded_at", "ts", "time"),
        "extra": data,
    }
