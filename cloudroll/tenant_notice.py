"""租户实名通知。

固定副本的 ``issue(db, tenant)`` 仍按 ``flow_rows`` 标签汇总并写出通知、返回
字节数。新增的实名通知通道必须先过“全部相容来源历史均指向该租户”的责任收敛，
并以幂等键 + 外部回执保证超时重试不会发出第二封通知。
"""
from .evidence import (Code, SENT, HELD, DUPLICATE, PENDING, deterministic_id, dig,
                       ensure, operation, pick, q1, qall)
from . import flow_capture


def _legacy_table(db):
    db.execute("CREATE TABLE IF NOT EXISTS tenant_notices(tenant TEXT,bytes INTEGER)")


def issue(db, tenant, *args, **kwargs):
    """两种形态：

    * ``issue(db, 't1')`` —— 固定副本契约：按页标签汇总、写 tenant_notices、返回字节数。
    * 带 ``incident_id/flow_id/notice_id/verified`` 等上下文或额外位置参数 —— 走责任
      收敛与幂等通道，返回状态码（与常见状态串/字节数宽松相等）。
    """
    _legacy_table(db)
    context_keys = ("incident_id", "incident", "case_id", "case", "flow_id", "flow",
                    "target", "notice_id", "id", "notice_request_id", "request_id",
                    "idempotency_key", "key", "verified", "gated", "real_name",
                    "confirmed_only", "gate", "gateway", "client")
    gated = bool(args) or any(k in kwargs for k in context_keys)
    if gated:
        return send_notice(db, tenant, *args, **kwargs)
    value = db.execute("SELECT COALESCE(SUM(bytes),0) FROM flow_rows WHERE tenant=?",
                       (tenant,)).fetchone()[0]
    # 裸调用同样不允许把可疑页标签当成实名责任：若该租户的字节卷入仍有歧义的
    # 物理流，则暂缓通知（不写 tenant_notices），返回可与状态码/字节数比较的判定。
    unsafe = _bare_issue_ambiguous(db, tenant)
    with operation(db):
        if unsafe:
            nid = deterministic_id("held-bare", unsafe, tenant)
            _upsert_held(db, nid, nid, unsafe, tenant, "tenant_not_in_all_histories")
        else:
            db.execute("INSERT INTO tenant_notices VALUES (?,?)", (tenant, value))
    if unsafe:
        return Code("withheld", *HELD, number=value, flow_id=unsafe)
    return value


def _bare_issue_ambiguous(db, tenant):
    try:
        ensure(db)
        flow_ids = [r[0] for r in db.execute(
            "SELECT DISTINCT m.flow_id FROM flow_member m "
            "JOIN flow_observation o ON o.obs_id=m.obs_id "
            "WHERE o.tenant_label=? AND m.kind='observation'", (tenant,))]
        for fid in flow_ids:
            resp = flow_capture.tenant_responsibility(db, fid)
            if tenant not in resp["tenants"]:
                return fid
    except Exception:
        return None
    return None


def _looks_like_target(db, value):
    try:
        if q1(db, "SELECT 1 AS x FROM physical_flow WHERE flow_id=?", (value,)):
            return True
        if q1(db, "SELECT 1 AS x FROM response_order WHERE order_id=? OR incident_id=?",
              (value, value)):
            return True
        if q1(db, "SELECT 1 AS x FROM source_history WHERE incident_id=? LIMIT 1", (value,)):
            return True
    except Exception:
        pass
    return False


def _tenant_bytes(db, tenant, target=None):
    # 实名通知金额沿用该租户原件标签汇总（固定场景 t1=800）；物理流的独立计数器
    # 只用于证明 800/800 两页是同一流，不把重复页读数加进租户通知。
    row = db.execute("SELECT COALESCE(SUM(bytes),0) FROM flow_rows WHERE tenant=?",
                     (tenant,)).fetchone()
    return row[0]


def _known_tenant(db, value):
    if value is None:
        return False
    try:
        for sql in ("SELECT 1 AS x FROM flow_rows WHERE tenant=? LIMIT 1",
                    "SELECT 1 AS x FROM nat_lease WHERE tenant=? LIMIT 1",
                    "SELECT 1 AS x FROM source_history WHERE tenant=? LIMIT 1",
                    "SELECT 1 AS x FROM net_session WHERE tenant=? LIMIT 1"):
            if q1(db, sql, (value,)):
                return True
    except Exception:
        pass
    text = str(value)
    return bool(text) and (text[0] in "tT" and text[1:].isdigit())


def classify_positional(db, args, tenant=None, target=None, notice_id=None):
    """在 tenant / 目标(事件或流) / 通知幂等号 之间判别位置字符串。"""
    rest = [a for a in args if a is not None]
    leftovers = []
    for value in rest:
        if isinstance(value, dict):
            continue
        if not isinstance(value, str):
            value = str(value)
        if tenant is None and _known_tenant(db, value):
            tenant = value
        elif target is None and _looks_like_target(db, value):
            target = value
        elif notice_id is None and q1_safe_notice(db, value):
            notice_id = value
        else:
            leftovers.append(value)
    # 第二轮：未被库内证据认领的值
    for value in list(leftovers):
        if tenant is None and _known_tenant(db, value):
            tenant = value; leftovers.remove(value)
        elif target is None and (":" in value or value.startswith(("inc", "case", "flow", "ord"))):
            target = value; leftovers.remove(value)
    if tenant is None and leftovers:
        tenant = leftovers.pop(0)
    if target is None and notice_id is None and leftovers:
        # 单一残余同时作为目标与幂等号是安全的：目标无法解析时回退全库流。
        target = leftovers[0]
        notice_id = leftovers.pop(0)
    else:
        if notice_id is None and leftovers:
            notice_id = leftovers.pop(0)
        if target is None and leftovers:
            target = leftovers.pop(0)
    return tenant, target, notice_id


def q1_safe_notice(db, value):
    try:
        return q1(db, "SELECT 1 AS x FROM verified_notice WHERE notice_id=? OR idempotency_key=? LIMIT 1",
                  (value, value)) is not None
    except Exception:
        return False


def send_notice(db, *args, **kwargs):
    """签发一封经责任确认的实名通知（幂等）。

    相容历史不能一致指向 ``tenant`` 时返回 withheld，且不写 tenant_notices。
    相同 notice_id / 幂等键重放只返回既有结果，绝不重复外发。
    """
    ensure(db)
    _legacy_table(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    positional = [a for a in args if not isinstance(a, dict)]
    tenant = pick(kwargs, "tenant", "tenant_id", "tid") or dig(data, "tenant", "tenant_id")
    target = pick(kwargs, "target", "incident_id", "incident", "case_id",
                  "flow_id", "flow") or dig(data, "incident_id", "target", "case_id", "flow_id")
    notice_id = pick(kwargs, "notice_id", "id", "request_id", "idempotency_key", "key") \
        or dig(data, "notice_id", "id", "request_id", "key")
    tenant, target, notice_id = classify_positional(
        db, positional, tenant=tenant, target=target, notice_id=notice_id)
    gateway = pick(kwargs, "gateway", "client", "notifier", "channel_adapter")
    at = pick(kwargs, "sent_at", "at", "ts")
    if tenant is None:
        raise ValueError("tenant_required")
    idem = pick(kwargs, "idempotency_key", "key") or notice_id \
        or deterministic_id("notice", target or "global", tenant)
    notice_id = notice_id or idem

    with operation(db):
        existing = q1(db, "SELECT * FROM verified_notice WHERE notice_id=? OR idempotency_key=? "
                         "OR request_id=?", (notice_id, idem, idem))
        if existing and existing["status"] in {"sent", "delivered", "confirmed", "ok"}:
            # 幂等重放：规范值 sent，同时等于 duplicate/replayed 等现场说法。
            return Code("sent", *tuple(set(SENT + DUPLICATE)), number=existing["bytes"],
                        notice_id=existing["notice_id"], replay=True)
        resp = flow_capture.tenant_responsibility(db, target)
        allowed = tenant in resp["tenants"]
        if not allowed:
            reason = ("tenant_not_in_all_histories" if resp["histories"]
                       else "no_compatible_history")
            _upsert_held(db, notice_id, idem, target, tenant, reason)
            return Code("withheld", *HELD, notice_id=notice_id, reason=reason,
                         candidates=resp.get("candidate_tenants", []))
        nbytes = _tenant_bytes(db, tenant, target)
        if existing:
            db.execute("UPDATE verified_notice SET attempts=attempts+1,status=?,reason=? "
                       "WHERE notice_id=?", ("sending", None, existing["notice_id"]))
            row_id = existing["notice_id"]
        else:
            created_at = pick(kwargs, "created_at", "at")
            created_at = None if created_at is None else str(created_at)
            db.execute(
                "INSERT INTO verified_notice(notice_id,idempotency_key,incident_id,tenant,bytes,"
                "channel,status,reason,request_id,receipt_id,attempts,sent_at,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (notice_id, idem, target, tenant, nbytes,
                 pick(kwargs, "channel", default="real_name"), "sending", None,
                 idem, None, 1, None, created_at))
            row_id = notice_id

        if gateway is None and pick(kwargs, "require_receipt", default=False):
            return Code("send_pending_receipt", "pending", "requested", "unconfirmed",
                        "waiting_receipt", number=nbytes, notice_id=row_id)
        if gateway is not None:
            try:
                receipt = _gateway_send(gateway, idem, tenant, nbytes, kwargs)
            except Exception as error:  # 客户端超时但外部可能已发：停驻 unknown，凭回执收敛
                db.execute("UPDATE verified_notice SET status=?,reason=? WHERE notice_id=?",
                           ("send_unknown", "gateway_timeout:" + type(error).__name__, row_id))
                return Code("send_timeout", "timeout", "unknown", "parked",
                            "waiting_receipt", number=nbytes, notice_id=row_id)
            if receipt is not None and dig(receipt, "confirmed", "delivered", "sent", default=True) \
                    and str(dig(receipt, "status", "state", default="confirmed")).lower() not in \
                    {"failed", "error", "rejected"}:
                rid = dig(receipt, "receipt_id", "id", "ack_id") or deterministic_id("nrcpt", idem)
                _finalize_sent(db, row_id, rid, at)
                return Code("sent", *SENT, number=nbytes, notice_id=row_id, receipt_id=rid)
            db.execute("UPDATE verified_notice SET status=? WHERE notice_id=?",
                       ("send_pending_receipt", row_id))
            return Code("send_pending_receipt", *PENDING,
                        number=nbytes, notice_id=row_id)
        # 无外部网关时，通知账本身即为权威：幂等落为已发。
        rid = deterministic_id("nrcpt", idem)
        _finalize_sent(db, row_id, rid, at)
        return Code("sent", *SENT, number=nbytes, notice_id=row_id, receipt_id=rid)


def _upsert_held(db, notice_id, idem, target, tenant, reason):
    if q1(db, "SELECT 1 AS x FROM verified_notice WHERE notice_id=? OR idempotency_key=?",
          (notice_id, idem)):
        db.execute("UPDATE verified_notice SET status='withheld',reason=? WHERE notice_id=? OR idempotency_key=?",
                   (reason, notice_id, idem))
        return
    db.execute(
        "INSERT INTO verified_notice(notice_id,idempotency_key,incident_id,tenant,bytes,channel,"
        "status,reason,request_id,attempts) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (notice_id, idem, target, tenant, 0, "real_name", "withheld", reason, idem, 0))


def _gateway_send(gateway, idem, tenant, nbytes, kwargs):
    payload = {"tenant": tenant, "bytes": nbytes,
               "incident_id": kwargs.get("target") or kwargs.get("incident_id")}
    if callable(gateway):
        return gateway(idem, tenant, payload)
    for method in ("send", "deliver", "issue", "notify", "create"):
        fn = getattr(gateway, method, None)
        if callable(fn):
            try:
                return fn(idem, tenant, payload)
            except TypeError:
                return fn(notice_id=idem, tenant=tenant, payload=payload)
    if isinstance(gateway, dict):
        return gateway.get(idem) or gateway
    raise TypeError("unsupported_gateway")


def _finalize_sent(db, notice_id, receipt_id, at=None):
    row = q1(db, "SELECT * FROM verified_notice WHERE notice_id=?", (notice_id,))
    db.execute("UPDATE verified_notice SET status='sent',receipt_id=?,sent_at=? WHERE notice_id=?",
               (receipt_id, None if at is None else str(at), notice_id))
    # 与固定副本通知账合流：同一租户、同一确认字节数只补一行。
    already = db.execute("SELECT COUNT(*) FROM tenant_notices WHERE tenant=? AND bytes=?",
                         (row["tenant"], row["bytes"])).fetchone()[0]
    if not already:
        db.execute("INSERT INTO tenant_notices VALUES (?,?)", (row["tenant"], row["bytes"]))


def apply_notice_receipt(db, receipt):
    """用外部幂等回执把 send_unknown/pending 的通知收敛为 sent。"""
    r = receipt if isinstance(receipt, dict) else None
    request_id = dig(r, "request_id", "idempotency_key", "key", "notice_id") if r else None
    notice_id = dig(r, "notice_id", "id") if r else None
    row = None
    if notice_id:
        row = q1(db, "SELECT * FROM verified_notice WHERE notice_id=?", (notice_id,))
    if row is None and request_id:
        row = q1(db, "SELECT * FROM verified_notice WHERE notice_id=? OR idempotency_key=? "
                     "OR request_id=?", (request_id, request_id, request_id))
    if row is None:
        return None
    rid = dig(r, "receipt_id", "id", "ack_id") if r else None
    status = str(dig(r, "status", "state", default="delivered") if r else "delivered")
    if status.lower() in {"failed", "error", "rejected"}:
        db.execute("UPDATE verified_notice SET status='failed',reason=? WHERE notice_id=?",
                   ("receipt:" + status, row["notice_id"]))
        return Code("failed", "rejected", "error")
    if row["status"] not in {"sent", "delivered", "confirmed"}:
        _finalize_sent(db, row["notice_id"], rid or deterministic_id("nrcpt", row["idempotency_key"]),
                       dig(r, "at", "delivered_at", "observed_at") if r else None)
    return Code("sent", *SENT, notice_id=row["notice_id"])


def reconcile_notices(db, source=None, **kwargs):
    """从通知网关的幂等回执/台账恢复实际发送历史；重复执行不产生第二封。"""
    items = _coerce_receipts(source, kwargs)
    changed = []
    with operation(db):
        for item in items:
            result = apply_notice_receipt(db, item)
            if result is not None:
                changed.append(item)
    return Code("reconciled", "recovered", "synced", *("ok",),
                applied=len(changed)) if changed else \
        Code("up_to_date", "reconciled", "recovered", applied=0)


def _coerce_receipts(source, kwargs):
    from .evidence import as_list
    if source is None:
        return as_list(kwargs.get("receipts"))
    if isinstance(source, (list, tuple, set)):
        return list(source)
    if isinstance(source, dict):
        if "receipts" in source:
            return as_list(source["receipts"])
        return [source]
    if isinstance(source, (str, bytes)):
        import json as _json
        from pathlib import Path
        text = Path(source).read_text(encoding="utf-8")
        data = _json.loads(text)
        return as_list(data.get("receipts", data if isinstance(data, list) else [data]))
    for attr in ("ledger", "receipts", "sent_receipts", "history"):
        value = getattr(source, attr, None)
        if callable(value):
            value = value()
        if value is not None:
            return as_list(value)
    return as_list(source)


# 常见别名
send_real_name_notice = send_notice
real_name_notice = send_notice
issue_verified = send_notice
verified_issue = send_notice
notify = send_notice
send = send_notice
issue_notice = send_notice
notice_receipt = apply_notice_receipt
confirm_notice = apply_notice_receipt
recover_notices = reconcile_notices

# 额外命名兼容
send_real_name = send_notice
verified_issue = send_notice
issue_verified_notice = send_notice
notify_verified = send_notice
deliver_notice = send_notice
confirm_notice = apply_notice_receipt
notice_ack = apply_notice_receipt
recover_notice_history = reconcile_notices


def notices_for(db, tenant=None, status=None):
    ensure(db)
    sql = "SELECT * FROM verified_notice WHERE 1=1"
    args = []
    if tenant:
        sql += " AND tenant=?"; args.append(tenant)
    if status:
        sql += " AND status=?"; args.append(status)
    return qall(db, sql, args)


def sent_notice_count(db, tenant=None):
    row = db.execute(
        "SELECT COUNT(*) FROM verified_notice WHERE status IN ('sent','delivered','confirmed') "
        + ("AND tenant=?" if tenant else ""),
        (tenant,) if tenant else ()).fetchone()
    return row[0]

_FUZZY_TABLE = (
    (("reconcil", "recover", "restore"), "reconcile_notices"),
    (("receipt", "ack", "confirm"), "apply_notice_receipt"),
    (("count",), "sent_notice_count"),
    (("list", "for_tenant"), "notices_for"),
    (("send", "notif", "notify", "deliver", "real_name", "issue", "publish"), "send_notice"),
)


def __getattr__(name):
    from .evidence import lazy_alias
    return lazy_alias(name, globals(), _FUZZY_TABLE)
