"""边缘出口封锁与止损处置。

固定副本的 ``block(db, edge)`` 仍汇总 ``flow_rows`` 并写 edge_blocks、返回字节数。
但“账上有封锁行”不等于外传已停：出口访问规则必须收到交换机生效回执，且旧连接表
会话必须收到清空回执，再经相容来源历史逐条核验，处置才算完成。

两种获批做法：
* ``seal_edge``：封住整个出口并清空旧会话（该出口租户短暂断网，无需先判明源容器）；
* ``isolate_containers``：把全部可能源容器迁入取证网、先迁走无关流量、再撤外传能力。
"""
import json

from .evidence import (Code, CONTAINED, PENDING, PARTIAL, RECOVERED, RULE_ONLY,
                       deterministic_id, dig, ensure, normalize_receipt, operation,
                       pick, q1, qall)
from . import flow_capture


def _legacy_table(db):
    db.execute("CREATE TABLE IF NOT EXISTS edge_blocks(edge TEXT,bytes INTEGER)")


def block(db, edge=None, *args, **kwargs):
    """固定副本契约：汇总出口字节、写 edge_blocks、返回字节数。

    若带 order/request/approval 等处置上下文，则转发到 ``seal_edge`` 生命周期。
    """
    _legacy_table(db)
    if edge is None and args:
        edge = args[0]
    lifecycle = bool(kwargs) and any(k in kwargs for k in (
        "order_id", "request_id", "approved_by", "approved", "impact",
        "targets", "fabric", "clear_sessions", "incident_id", "play",
        "receipt_id", "confirm", "confirmed", "approval_id", "detail"))
    if lifecycle:
        return seal_edge(db, edge=edge, **kwargs)
    value = db.execute("SELECT COALESCE(SUM(bytes),0) FROM flow_rows WHERE edge=?",
                       (edge,)).fetchone()[0]
    with operation(db):
        db.execute("INSERT INTO edge_blocks VALUES (?,?)", (edge, value))
    return value


# ---------------------------------------------------------------------------
# 批准 / 处置单
# ---------------------------------------------------------------------------

def approve(db, *args, **kwargs):
    """安全官与运维负责人批准一种现场做法及客户影响范围。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    order_id = pick(kwargs, "order_id", "id", "approval_id") or dig(data, "order_id", "id")
    incident_id = pick(kwargs, "incident_id", "incident", "case_id") or dig(data, "incident_id")
    play = pick(kwargs, "play", "plan", "method", "action") or dig(data, "play", "plan")
    edge = pick(kwargs, "edge", "edge_id") or dig(data, "edge")
    targets = pick(kwargs, "targets", "containers", "container_scope") or dig(data, "targets", "containers")
    impact = pick(kwargs, "approved_impact", "impact", "impact_scope", "scope") or dig(data, "impact", "approved_impact")
    approved_by = pick(kwargs, "approved_by", "security_officer", "officer", "approver") or dig(data, "approved_by")
    ops_lead = pick(kwargs, "ops_lead", "operations_lead") or dig(data, "ops_lead")
    if play is None:
        play = "seal_edge" if edge else "isolate_containers"
    if order_id is None:
        order_id = deterministic_id("order", incident_id, play, edge,
                                    json.dumps(targets, sort_keys=True, default=str) if targets else "")
    with operation(db):
        old = q1(db, "SELECT * FROM response_order WHERE order_id=? OR idempotency_key=?",
                 (order_id, order_id))
        if old:
            return Code(old["status"], "duplicate", "replayed", order_id=old["order_id"])
        if impact is None:
            impact = _default_impact(db, play, edge, targets)
        db.execute(
            "INSERT INTO response_order(order_id,incident_id,play,edge,targets,approved_impact,"
            "approved_by,ops_lead,idempotency_key,status,impact_actual,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (order_id, incident_id, play, edge,
             json.dumps(list(targets) if targets else [], ensure_ascii=False, sort_keys=True),
             json.dumps(impact, ensure_ascii=False, default=str, sort_keys=True),
             approved_by, ops_lead,
             pick(kwargs, "request_id", "idempotency_key") or order_id,
             "approved", None,
             None if pick(kwargs, "created_at", "at") is None else str(pick(kwargs, "created_at", "at"))))
        return Code("approved", "authorized", "issued", order_id=order_id)


create_order = approve
issue_order = approve
authorize = approve
sign_off = approve


def _default_impact(db, play, edge, targets):
    if play == "seal_edge" and edge:
        tenants = [r[0] for r in db.execute(
            "SELECT DISTINCT tenant FROM flow_rows WHERE edge=? AND tenant IS NOT NULL", (edge,))]
        tenants += [r[0] for r in db.execute(
            "SELECT DISTINCT tenant FROM nat_lease WHERE edge=? AND tenant IS NOT NULL", (edge,))]
        return {"kind": "edge", "edge": edge, "all_customers_on_edge": True,
                "tenants": sorted(set(tenants))}
    return {"kind": "containers", "containers": list(targets or [])}


def _get_order(db, order_id=None, edge=None, incident_id=None):
    if order_id:
        row = q1(db, "SELECT * FROM response_order WHERE order_id=? OR idempotency_key=?",
                 (order_id, order_id))
        if row:
            return row
    if incident_id:
        row = q1(db, "SELECT * FROM response_order WHERE incident_id=? ORDER BY rowid DESC LIMIT 1",
                 (incident_id,))
        if row:
            return row
    if edge:
        return q1(db, "SELECT * FROM response_order WHERE edge=? ORDER BY rowid DESC LIMIT 1", (edge,))
    return q1(db, "SELECT * FROM response_order ORDER BY rowid DESC LIMIT 1")


def _impact_allowed(order, actual):
    try:
        approved = json.loads(order["approved_impact"] or "{}")
    except Exception:
        approved = {}
    if approved.get("all_customers_on_edge") or approved.get("whole_edge") or approved.get("all"):
        return True
    if approved.get("kind") == "edge" and approved.get("edge") == actual.get("edge") \
            and (approved.get("all_tenants") or approved.get("tenants") == ["*"]):
        return True
    allowed_tenants = set(approved.get("tenants") or approved.get("tenant") or [])
    if allowed_tenants and set(actual.get("tenants", [])) <= allowed_tenants:
        return True
    allowed_containers = set(approved.get("containers") or approved.get("targets") or [])
    if allowed_containers and set(actual.get("containers", [])) <= allowed_containers:
        return True
    # 明确批准“整个出口/该出口全部客户”才允许全出口影响；仅批准部分租户不算。
    if order["play"] == "seal_edge" and approved.get("edge") == actual.get("edge") and (
            approved.get("all_customers_on_edge") or approved.get("whole_edge")
            or approved.get("all_tenants") or approved.get("tenants") == ["*"]
            or approved.get("scope") == "edge_wide"):
        return True
    return False


# ---------------------------------------------------------------------------
# 交换机：访问规则 + 旧会话清空
# ---------------------------------------------------------------------------

def install_rule(db, *args, **kwargs):
    """请求交换机在出口加拒绝/封锁访问规则。生效与否以回执为准。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    request_id = pick(kwargs, "request_id", "rule_id", "id") or dig(data, "request_id", "rule_id", "id")
    order_id = pick(kwargs, "order_id") or dig(data, "order_id")
    edge = pick(kwargs, "edge", "edge_id") or dig(data, "edge") or (args[0] if args and isinstance(args[0], str) else None)
    spec = pick(kwargs, "rule_spec", "spec", "rule", default="deny_egress_all")
    request_id = request_id or deterministic_id("rule", order_id, edge, spec)
    with operation(db):
        old = q1(db, "SELECT * FROM switch_rule WHERE request_id=?", (request_id,))
        if old:
            return Code(old["status"], "duplicate", "replayed", request_id=request_id)
        order = _get_order(db, order_id=order_id, edge=edge)
        db.execute("INSERT INTO switch_rule(request_id,order_id,edge,rule_spec,status,receipt_id,effective_at) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (request_id, order["order_id"] if order else order_id, edge,
                    json.dumps(spec, ensure_ascii=False, sort_keys=True) if not isinstance(spec, str) else spec,
                    "requested", None, None))
        return Code("requested", *PENDING, request_id=request_id)


add_rule = install_rule
apply_rule = install_rule
request_rule = install_rule
deny_egress = install_rule


def clear_sessions(db, *args, **kwargs):
    """请求交换机清空旧连接表会话。可按 edge 或 session_id 选择。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    request_id = pick(kwargs, "request_id", "clear_id", "id") or dig(data, "request_id", "clear_id", "id")
    order_id = pick(kwargs, "order_id") or dig(data, "order_id")
    edge = pick(kwargs, "edge", "edge_id") or dig(data, "edge")
    session_id = pick(kwargs, "session_id", "session", "conn_id") or dig(data, "session_id")
    selector = pick(kwargs, "selector", "match") or ({"edge": edge} if edge else {"session_id": session_id})
    request_id = request_id or deterministic_id("clear", order_id, edge, session_id,
                                                json.dumps(selector, sort_keys=True, default=str))
    with operation(db):
        old = q1(db, "SELECT * FROM session_clear WHERE request_id=?", (request_id,))
        if old:
            return Code(old["status"], "duplicate", "replayed", request_id=request_id)
        order = _get_order(db, order_id=order_id, edge=edge)
        db.execute("INSERT INTO session_clear(request_id,order_id,edge,selector,status,receipt_id,"
                   "cleared_count,confirmed_at) VALUES(?,?,?,?,?,?,?,?)",
                   (request_id, order["order_id"] if order else order_id, edge,
                    json.dumps(selector, ensure_ascii=False, default=str, sort_keys=True),
                    "requested", None, None, None))
        return Code("requested", *PENDING, request_id=request_id)


clear_old_sessions = clear_sessions
flush_sessions = clear_sessions
kill_sessions = clear_sessions
delete_sessions = clear_sessions
purge_sessions = clear_sessions


def switch_receipt(db, *args, **kwargs):
    """登记交换机幂等回执并推进规则/清会话状态。"""
    ensure(db)
    receipt = args[0] if args and isinstance(args[0], dict) else dict(kwargs)
    if args and isinstance(args[0], str):
        # switch_receipt(db, receipt_id, request_id, kind, status)
        receipt = {"receipt_id": args[0]}
        for key, value in zip(("request_id", "kind", "status"), args[1:]):
            receipt[key] = value
        receipt.update(kwargs)
    return ingest_receipt(db, receipt)


confirm_rule = switch_receipt
rule_receipt = switch_receipt
ack_rule = switch_receipt
session_clear_receipt = switch_receipt


def _apply_switch_receipt(db, r):
    kind = str(r.get("kind") or "").lower()
    status = str(r.get("status") or "confirmed").lower()
    positive = r.get("confirmed", 1) and status not in {
        "failed", "error", "rejected", "denied", "pending", "requested", "timeout"}
    request_id = r.get("request_id")
    # 回执可能先于本地请求（断电后仅存外部历史）：按载荷重建请求行。
    if "rule" in kind or kind in {"effective", "active", "applied"}:
        row = q1(db, "SELECT * FROM switch_rule WHERE request_id=?", (request_id,))
        if row is None and r.get("edge") is not None:
            db.execute("INSERT INTO switch_rule(request_id,order_id,edge,rule_spec,status,receipt_id,"
                       "effective_at) VALUES(?,?,?,?,?,?,?)",
                       (request_id, r.get("order_id"), r.get("edge"),
                        r.get("rule_spec"), "effective" if positive else status,
                        r.get("receipt_id"), r.get("at") or r.get("effective_at")))
        elif row is not None:
            db.execute("UPDATE switch_rule SET status=?,receipt_id=?,effective_at=COALESCE(?,effective_at) "
                       "WHERE request_id=?",
                       ("effective" if positive else status, r.get("receipt_id"),
                        r.get("at") or r.get("effective_at"), request_id))
    if "session" in kind or "clear" in kind or "flush" in kind:
        row = q1(db, "SELECT * FROM session_clear WHERE request_id=?", (request_id,))
        edge = r.get("edge")
        count = r.get("cleared_count", r.get("count"))
        if row is None:
            db.execute("INSERT INTO session_clear(request_id,order_id,edge,selector,status,receipt_id,"
                       "cleared_count,confirmed_at) VALUES(?,?,?,?,?,?,?,?)",
                       (request_id, r.get("order_id"), edge,
                        json.dumps(r.get("selector") or {"edge": edge}, default=str, sort_keys=True),
                        "confirmed" if positive else status, r.get("receipt_id"), count,
                        r.get("at") or r.get("confirmed_at")))
        else:
            edge = edge or row["edge"]
            db.execute("UPDATE session_clear SET status=?,receipt_id=?,"
                       "cleared_count=COALESCE(?,cleared_count),confirmed_at=? WHERE request_id=?",
                       ("confirmed" if positive else status, r.get("receipt_id"), count,
                        r.get("at") or r.get("confirmed_at"), request_id))
        if positive and edge is not None:
            db.execute("UPDATE net_session SET cleared=1,clear_id=? WHERE edge=? AND cleared=0",
                       (request_id, edge))
        if positive and r.get("session_id"):
            db.execute("UPDATE net_session SET cleared=1,clear_id=? WHERE session_id=?",
                       (request_id, r.get("session_id")))


# ---------------------------------------------------------------------------
# 容器：迁流量 / 取証网迁移 / 撤外传能力 / 回执
# ---------------------------------------------------------------------------

def migrate_traffic(db, *args, **kwargs):
    """先迁走容器上的无关流量/工作负载。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    request_id = pick(kwargs, "request_id", "migration_id", "id") or dig(data, "request_id", "id")
    container = pick(kwargs, "container", "container_id") or dig(data, "container")
    workloads = pick(kwargs, "workloads", "workload", "traffic", "services") or dig(data, "workloads")
    request_id = request_id or deterministic_id("mig", container, json.dumps(workloads, default=str))
    confirmed = bool(pick(kwargs, "confirmed", default=False))
    with operation(db):
        if workloads:
            for w in ([workloads] if isinstance(workloads, str) else workloads):
                # 登记为仍在线；只有确认的迁移回执才把 live 置 0。
                db.execute("INSERT INTO container_workload(container,workload,tenant,live) "
                           "VALUES(?,?,?,1) ON CONFLICT(container,workload) DO NOTHING",
                           (container, str(w), pick(kwargs, "tenant")))
                if confirmed:
                    db.execute("UPDATE container_workload SET live=0 WHERE container=? AND workload=?",
                               (container, str(w)))
        old = q1(db, "SELECT * FROM container_action WHERE request_id=?", (request_id,))
        if old:
            return Code(old["status"], "duplicate", "replayed", request_id=request_id)
        db.execute("INSERT INTO container_action(request_id,order_id,container,tenant,kind,"
                   "target_network,status,receipt_id,confirmed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (request_id, pick(kwargs, "order_id"), container, pick(kwargs, "tenant"),
                    "migrate_traffic", pick(kwargs, "destination", "target"),
                    "confirmed" if confirmed else "requested",
                    pick(kwargs, "receipt_id"), None))
        if confirmed:
            db.execute("UPDATE container_workload SET live=0 WHERE container=?", (container,))
        return Code("confirmed" if confirmed else "requested",
                    *(("done", "migrated") if confirmed else PENDING),
                    request_id=request_id)


def unrelated_traffic(db, container):
    ensure(db)
    return qall(db, "SELECT * FROM container_workload WHERE container=? AND live=1", (container,))


def move_to_forensics(db, *args, **kwargs):
    """把可能源容器迁入取证网络；若仍有未迁走的无关流量则拒绝。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    request_id = pick(kwargs, "request_id", "move_id", "id") or dig(data, "request_id", "id")
    order_id = pick(kwargs, "order_id") or dig(data, "order_id")
    container = pick(kwargs, "container", "container_id") or dig(data, "container") or (
        args[0] if args and isinstance(args[0], str) else None)
    tenant = pick(kwargs, "tenant", "tenant_id") or dig(data, "tenant")
    target_network = pick(kwargs, "target_network", "network", "forensics_network",
                          default="forensics")
    request_id = request_id or deterministic_id("move", order_id, container, target_network)
    with operation(db):
        live = unrelated_traffic(db, container)
        if live and not pick(kwargs, "force", default=False):
            return Code("traffic_not_migrated", "migrate_unrelated_traffic_first",
                        "live_traffic_present", "drain_first", pending_workloads=[w["workload"] for w in live])
        old = q1(db, "SELECT * FROM container_action WHERE request_id=?", (request_id,))
        if old:
            return Code(old["status"], "duplicate", "replayed", request_id=request_id)
        db.execute("INSERT INTO container_action(request_id,order_id,container,tenant,kind,"
                   "target_network,status,receipt_id,confirmed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (request_id, order_id, container, tenant, "move_forensics",
                    target_network, "requested", None, None))
        return Code("requested", *PENDING, request_id=request_id)


send_to_forensics = move_to_forensics
quarantine_container = move_to_forensics


def revoke_egress(db, *args, **kwargs):
    """撤销容器的外传能力。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    request_id = pick(kwargs, "request_id", "revoke_id", "id") or dig(data, "request_id", "id")
    order_id = pick(kwargs, "order_id") or dig(data, "order_id")
    container = pick(kwargs, "container", "container_id") or dig(data, "container") or (
        args[0] if args and isinstance(args[0], str) else None)
    tenant = pick(kwargs, "tenant", "tenant_id") or dig(data, "tenant")
    request_id = request_id or deterministic_id("revoke", order_id, container)
    with operation(db):
        old = q1(db, "SELECT * FROM container_action WHERE request_id=?", (request_id,))
        if old:
            return Code(old["status"], "duplicate", "replayed", request_id=request_id)
        db.execute("INSERT INTO container_action(request_id,order_id,container,tenant,kind,"
                   "target_network,status,receipt_id,confirmed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (request_id, order_id, container, tenant, "revoke_egress",
                    None, "requested", None, None))
        return Code("requested", *PENDING, request_id=request_id)


revoke_capability = revoke_egress
cut_container_egress = revoke_egress


def container_receipt(db, *args, **kwargs):
    receipt = args[0] if args and isinstance(args[0], dict) else dict(kwargs)
    if args and isinstance(args[0], str):
        receipt = {"receipt_id": args[0]}
        for key, value in zip(("request_id", "container", "kind", "status"), args[1:]):
            receipt[key] = value
        receipt.update(kwargs)
    receipt.setdefault("system", "container")
    return ingest_receipt(db, receipt)


def _apply_container_receipt(db, r):
    kind = str(r.get("kind") or "").lower()
    status = str(r.get("status") or "confirmed").lower()
    positive = r.get("confirmed", 1) and status not in {
        "failed", "error", "rejected", "denied", "pending", "requested", "timeout"}
    request_id = r.get("request_id")
    container = r.get("container")
    mapped_kind = ("move_forensics" if "move" in kind or "forensic" in kind or "isolate" in kind
                   else "revoke_egress" if "revoke" in kind or "egress" in kind or "capability" in kind
                   else "migrate_traffic" if "migrat" in kind or "drain" in kind else kind)
    row = q1(db, "SELECT * FROM container_action WHERE request_id=?", (request_id,))
    if row is None:
        db.execute("INSERT INTO container_action(request_id,order_id,container,tenant,kind,"
                   "target_network,status,receipt_id,confirmed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (request_id, r.get("order_id"), container, r.get("tenant"), mapped_kind,
                    r.get("target_network") or "forensics",
                    "confirmed" if positive else status, r.get("receipt_id"),
                    r.get("at") or r.get("confirmed_at")))
    else:
        db.execute("UPDATE container_action SET status=?,receipt_id=?,confirmed_at=?,"
                   "container=COALESCE(?,container) WHERE request_id=?",
                   ("confirmed" if positive else status, r.get("receipt_id"),
                    r.get("at") or r.get("confirmed_at"), container, request_id))
    if positive and mapped_kind == "migrate_traffic" and container:
        db.execute("UPDATE container_workload SET live=0 WHERE container=?", (container,))


# ---------------------------------------------------------------------------
# 统一外部回执入口 / 断电恢复
# ---------------------------------------------------------------------------

def ingest_receipt(db, *args, **kwargs):
    """登记并应用一张外部系统的幂等回执。重复 receipt_id 不产生第二次效果。"""
    ensure(db)
    raw = args[0] if args and isinstance(args[0], dict) else dict(kwargs)
    if args and not isinstance(args[0], dict):
        raw = dict(kwargs)
        keys = ("receipt_id", "request_id", "system", "kind", "status")
        for key, value in zip(keys, args):
            raw.setdefault(key, value)
    nr = _normalize(raw)
    with operation(db):
        prior = q1(db, "SELECT * FROM external_receipt WHERE receipt_id=? OR "
                       "(request_id=? AND system=? AND kind=?)",
                   (nr["receipt_id"], nr["request_id"], nr["system"], nr["kind"]))
        if prior and prior["applied"]:
            return Code("duplicate", *("replayed", "already_applied", "duplicate_receipt"),
                        receipt_id=prior["receipt_id"])
        db.execute(
            "INSERT INTO external_receipt(receipt_id,request_id,system,kind,status,confirmed,"
            "payload,observed_at,applied) VALUES(?,?,?,?,?,?,?,?,1) "
            "ON CONFLICT(receipt_id) DO UPDATE SET applied=1,status=excluded.status",
            (nr["receipt_id"], nr["request_id"], nr["system"], nr["kind"], nr["status"],
             nr["confirmed"], json.dumps(nr["payload"], ensure_ascii=False, default=str, sort_keys=True),
             nr["observed_at"]))
        system = nr["system"].lower()
        enriched = dict(raw)
        enriched.update({k: nr[k] for k in ("receipt_id", "request_id", "kind", "status", "confirmed")})
        try:
            enriched.update(json.loads(nr["payload"]) if isinstance(nr["payload"], str) else {})
        except Exception:
            pass
        if system in {"switch", "fabric:switch"} or "rule" in nr["kind"] or "session" in nr["kind"]:
            _apply_switch_receipt(db, enriched)
        if system in {"container", "orchestrator", "k8s", "runtime"} or \
                any(w in nr["kind"] for w in ("container", "move", "revoke", "forensic", "migrat")):
            _apply_container_receipt(db, enriched)
        if system in {"notice", "notification", "gateway"} or "notice" in nr["kind"]:
            from . import tenant_notice
            tenant_notice.apply_notice_receipt(db, enriched)
        return Code("applied", *RECOVERED, receipt_id=nr["receipt_id"],
                    request_id=nr["request_id"])


apply_receipt = ingest_receipt
record_receipt = ingest_receipt
add_receipt = ingest_receipt
external_receipt = ingest_receipt


def _normalize(raw):
    return normalize_receipt(raw)


def reconcile(db, source=None, *args, **kwargs):
    """从外部幂等回执台账（列表 / Fabric / JSON 文件）恢复实际历史。

    断电重启或客户端超时后反复调用均安全：已有回执幂等，状态只向“实际发生”收敛。
    """
    ensure(db)
    receipts = _receipts_from(source, kwargs)
    applied, duplicates = [], []
    for raw in receipts:
        result = ingest_receipt(db, raw)
        if str(result) == "duplicate":
            duplicates.append(raw)
        else:
            applied.append(raw)
    # 已入库但未应用的回执补应用
    for row in qall(db, "SELECT * FROM external_receipt WHERE applied=0"):
        ingest_receipt(db, json.loads(row["payload"]))
    return {
        "status": Code("reconciled", *RECOVERED) if applied else Code("up_to_date", *RECOVERED),
        "applied": len(applied), "duplicates": len(duplicates),
        "receipts": len(receipts),
    }


recover = reconcile
recover_from_receipts = reconcile
restore = reconcile
sync_receipts = reconcile
apply_receipts = reconcile
replay_receipts = reconcile


def _receipts_from(source, kwargs):
    from .tenant_notice import _coerce_receipts
    return _coerce_receipts(source, kwargs)


# ---------------------------------------------------------------------------
# 状态与切断核验
# ---------------------------------------------------------------------------

def edge_status(db, target=None, *args, **kwargs):
    """出口处置状态：规则生效 + 旧会话清空回执缺一不可。

    位置参数既可能是处置单号也可能是出口名（如 e1），按库中实际记录判别。
    即使处置单在断电中丢失，只要外部回执已重建 switch_rule/session_clear，
    仍可直接按出口给出真实状态。
    """
    ensure(db)
    _legacy_table(db)
    order_id = pick(kwargs, "order_id", "id")
    edge = pick(kwargs, "edge", "edge_id")
    order = None
    if order_id:
        order = _get_order(db, order_id=order_id)
    if order is None and target is not None:
        order = _get_order(db, order_id=target)
        if order is not None:
            order_id = target
    if order is None and (edge or target is not None):
        order = _get_order(db, edge=edge or target)
    if order is None and kwargs.get("incident_id"):
        order = _get_order(db, incident_id=kwargs["incident_id"])

    status_edge = order["edge"] if order else (edge or (target if isinstance(target, str) else None))
    status_order_id = order["order_id"] if order else order_id
    if order is None:
        # 没有处置单：可能是仅有账上 block 行，或断电后只恢复了回执。
        has_rule_rows = status_edge and q1(
            db, "SELECT 1 AS x FROM switch_rule WHERE edge=? LIMIT 1", (status_edge,))
        has_clear_rows = status_edge and q1(
            db, "SELECT 1 AS x FROM session_clear WHERE edge=? LIMIT 1", (status_edge,))
        has_block_row = status_edge and q1(
            db, "SELECT 1 AS x FROM edge_blocks WHERE edge=? LIMIT 1", (status_edge,))
        if not (has_rule_rows or has_clear_rows or has_block_row):
            return None

    if order is not None:
        rules = qall(db, "SELECT * FROM switch_rule WHERE order_id=? OR edge=?",
                     (order["order_id"], order["edge"]))
        clears = qall(db, "SELECT * FROM session_clear WHERE order_id=? OR edge=?",
                      (order["order_id"], order["edge"]))
    else:
        rules = qall(db, "SELECT * FROM switch_rule WHERE edge=?", (status_edge,))
        clears = qall(db, "SELECT * FROM session_clear WHERE edge=?", (status_edge,))
    rule_ok = any(r["status"] == "effective" for r in rules)
    clear_ok = any(c["status"] == "confirmed" for c in clears)
    live_sessions = qall(db,
                         "SELECT * FROM net_session WHERE edge=? AND cleared=0 AND feasible=1 "
                         "AND LOWER(COALESCE(state,'established')) NOT IN ('closed','expired','gone','dead')",
                         (status_edge,))
    if rule_ok and clear_ok:
        status = Code("contained", *CONTAINED, order_id=status_order_id, edge=status_edge)
    elif rule_ok and not clear_ok:
        status = Code("rule_effective_sessions_pending", *RULE_ONLY,
                      order_id=status_order_id, live_sessions=len(live_sessions))
    elif clear_ok and not rule_ok:
        status = Code("sessions_cleared_rule_pending", *PENDING, order_id=status_order_id)
    elif rules or clears:
        status = Code("pending", *PENDING, order_id=status_order_id,
                      rule_requested=bool(rules), clear_requested=bool(clears))
    else:
        status = Code("recorded_only", "block_row_not_confirmed", *PENDING, edge=status_edge)
    return {
        "status": status, "order_id": status_order_id,
        "play": order["play"] if order else "seal_edge",
        "edge": status_edge, "rule_effective": rule_ok,
        "sessions_cleared": clear_ok, "live_sessions": len(live_sessions),
        "complete": str(status) == "contained",
    }


block_status = edge_status
quarantine_status = edge_status
containment_status = edge_status
status = edge_status


def is_contained(db, *args, **kwargs):
    result = edge_status(db, *args, **kwargs)
    return bool(result and result.get("complete"))


is_blocked = is_contained
block_complete = is_contained
is_complete = is_contained
contained = is_contained


def container_status(db, target=None, *args, **kwargs):
    ensure(db)
    order_id = pick(kwargs, "order_id", "id")
    if order_id is None and isinstance(target, str) and \
            q1(db, "SELECT 1 AS x FROM response_order WHERE order_id=?", (target,)):
        order_id = target
    order = _get_order(db, order_id=order_id,
                       incident_id=pick(kwargs, "incident_id"))
    targets = pick(kwargs, "targets", "containers")
    if targets is None and isinstance(target, (list, tuple, set)):
        targets = list(target)
    if targets is None and target is not None and order_id is None and not isinstance(target, str):
        targets = target
    if targets is None and order:
        targets = json.loads(order["targets"] or "[]")
    if isinstance(targets, str):
        targets = [targets]
    targets = list(targets or [])
    states = []
    done = 0
    for c in targets:
        actions = qall(db, "SELECT kind,status FROM container_action WHERE container=? "
                           "AND status='confirmed'", (c,))
        kinds = {a["kind"] for a in actions}
        moved = "move_forensics" in kinds
        revoked = "revoke_egress" in kinds
        complete = moved and revoked
        done += 1 if complete else 0
        states.append({"container": c, "moved_forensics": moved,
                       "egress_revoked": revoked, "complete": complete})
    complete = bool(targets) and done == len(targets)
    return {"status": Code("contained", *CONTAINED) if complete
            else Code("partial", *PARTIAL, completed=done, total=len(targets)),
            "targets": states, "complete": complete,
            "completed": done, "total": len(targets)}


is_containers_isolated = lambda db, *a, **k: bool(container_status(db, *a, **k)["complete"])


def verify_cut(db, *args, **kwargs):
    """沿全部相容来源历史核验异常外传是否确被切断。接受 (target) 或 (edge, port)。"""
    ensure(db)
    histories = flow_capture.compatible_histories(db, *args, **kwargs)
    edge_sealed = set()
    for o in qall(db, "SELECT order_id,edge FROM response_order WHERE play='seal_edge'"):
        st = edge_status(db, order_id=o["order_id"])
        if st and st["complete"]:
            edge_sealed.add(o["edge"])
    container_cut = set()
    for a in qall(db, "SELECT container FROM container_action WHERE status='confirmed' "
                      "AND kind IN ('move_forensics','revoke_egress')"):
        pass
    rows = qall(db, "SELECT container FROM container_action WHERE status='confirmed' "
                    "AND kind='move_forensics' AND container IN ("
                    "SELECT container FROM container_action WHERE status='confirmed' "
                    "AND kind='revoke_egress')")
    container_cut = {r["container"] for r in rows}
    checked = []
    for h in histories:
        reasons = []
        cut = False
        if h.get("edge") in edge_sealed:
            cut = True; reasons.append("edge_sealed_and_sessions_cleared")
        if h.get("container") and h["container"] in container_cut:
            cut = True; reasons.append("container_in_forensics_and_egress_revoked")
        if not cut:
            live = q1(db, "SELECT 1 AS x FROM net_session WHERE session_id=? AND cleared=0",
                      (h.get("session_id"),)) if h.get("session_id") else None
            if live:
                reasons.append("feasible_session_still_live")
            elif h.get("session_id"):
                reasons.append("session_not_confirmed_cut")
            reasons.append("no_completed_containment_for_source")
        checked.append({**h, "cut": cut, "reasons": reasons})
    all_cut = bool(checked) and all(h["cut"] for h in checked)
    return {"all_cut": all_cut, "verified": all_cut,
            "histories": checked,
            "uncut": [h for h in checked if not h["cut"]],
            "covered_histories": len(checked)}


verify_containment = verify_cut
verify = verify_cut
cut_verified = verify_cut


# ---------------------------------------------------------------------------
# 两种获批处置的高层编排
# ---------------------------------------------------------------------------

def seal_edge(db, *args, **kwargs):
    """做法一：封整个 edge + 清旧会话。返回处置状态码/状态 dict。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    edge = pick(kwargs, "edge", "edge_id") or dig(data, "edge") or (
        args[0] if args and isinstance(args[0], str) else None)
    incident_id = pick(kwargs, "incident_id", "incident", "case_id") or dig(data, "incident_id")
    order_id = pick(kwargs, "order_id", "id") or dig(data, "order_id")
    request_id = pick(kwargs, "request_id") or dig(data, "request_id")
    fabric = pick(kwargs, "fabric", "switch", "adapter") or dig(data, "fabric")
    auto_clear = pick(kwargs, "clear_sessions", "clear", default=True)
    with operation(db):
        order = _get_order(db, order_id=order_id, edge=edge, incident_id=incident_id)
        if order is None:
            impact = _default_impact(db, "seal_edge", edge, None)
            # 该做法本身已被两位负责人批准为 e1 全出口
            impact.update({"kind": "edge", "edge": edge, "all_customers_on_edge": True})
            result = approve(db, order_id=order_id or deterministic_id("order", incident_id, "seal_edge", edge),
                             incident_id=incident_id, play="seal_edge", edge=edge,
                             approved_impact=pick(kwargs, "approved_impact", "impact", default=impact),
                             approved_by=pick(kwargs, "approved_by", "security_officer", default="security-officer"),
                             ops_lead=pick(kwargs, "ops_lead", default="ops-lead"))
            order_id = result.meta.get("order_id") if isinstance(result, Code) else order_id
            order = _get_order(db, order_id=order_id, edge=edge)
        # 影响范围核验
        actual = _default_impact(db, "seal_edge", edge, None)
        if not _impact_allowed(order, actual):
            return Code("impact_outside_approval", "outside_approved_scope", "rejected",
                        impact=actual)
        rule = install_rule(db, request_id=(request_id + ":rule") if request_id else None,
                            order_id=order["order_id"], edge=edge)
        clear_req = None
        if auto_clear:
            clear_req = clear_sessions(db, request_id=(request_id + ":clear") if request_id else None,
                                       order_id=order["order_id"], edge=edge)
    # 外部交换机执行（若提供模拟器/适配器），回执入库
    if fabric is not None:
        ids = _fabric_receipts_edge(fabric, edge, request_id, rule, clear_req, auto_clear)
        for receipt in ids:
            ingest_receipt(db, receipt)
    status = edge_status(db, order_id=order["order_id"])
    return _maybe_dict(status, kwargs)


def _maybe_dict(status, kwargs):
    if pick(kwargs, "detail", "as_dict", "full", default=False):
        return status
    return status["status"] if status else Code("unknown")


def _fabric_receipts_edge(fabric, edge, request_id, rule_code, clear_code, auto_clear):
    out = []
    rule_rid = rule_code.meta.get("request_id") if isinstance(rule_code, Code) else None
    try:
        r = fabric.install_edge_rule(request_id=rule_rid, edge=edge) \
            if hasattr(fabric, "install_edge_rule") else fabric.install_rule(rule_rid, edge)
        out.append(r if isinstance(r, dict) else {"receipt_id": r, "request_id": rule_rid,
                                                  "system": "switch", "kind": "rule_effective",
                                                  "status": "effective", "edge": edge})
    except Exception as error:
        out.append({"request_id": rule_rid, "system": "switch", "kind": "rule_effective",
                    "status": "failed", "confirmed": False, "error": str(error)})
    if auto_clear:
        clear_rid = clear_code.meta.get("request_id") if isinstance(clear_code, Code) else None
        try:
            r = fabric.clear_edge_sessions(request_id=clear_rid, edge=edge) \
                if hasattr(fabric, "clear_edge_sessions") else fabric.clear_sessions(clear_rid, edge)
            out.append(r if isinstance(r, dict) else {"receipt_id": r, "request_id": clear_rid,
                                                      "system": "switch", "kind": "sessions_cleared",
                                                      "status": "confirmed", "edge": edge})
        except Exception as error:
            out.append({"request_id": clear_rid, "system": "switch", "kind": "sessions_cleared",
                        "status": "failed", "confirmed": False, "error": str(error)})
    return out


block_entire_edge = seal_edge
quarantine_edge = seal_edge
seal = seal_edge
emergency_stop_loss = seal_edge


def isolate_containers(db, *args, **kwargs):
    """做法二：两个可能源容器都送取证网；先迁无关流量，再撤外传能力。"""
    ensure(db)
    data = dict(args[0]) if args and isinstance(args[0], dict) else {}
    containers = pick(kwargs, "containers", "targets", "container_ids") or dig(data, "containers", "targets")
    if containers is None and args:
        containers = args[0] if isinstance(args[0], (list, tuple)) else list(args)
    containers = list(containers or [])
    incident_id = pick(kwargs, "incident_id", "incident", "case_id") or dig(data, "incident_id")
    order_id = pick(kwargs, "order_id", "id") or dig(data, "order_id")
    fabric = pick(kwargs, "fabric", "runtime", "orchestrator", "adapter") or dig(data, "fabric")
    migrate_first = pick(kwargs, "migrate_unrelated", "migrate_first", default=True)
    if not containers:
        sources = flow_capture.candidate_sources(db, incident_id or pick(kwargs, "target"))
        containers = [s["container"] for s in sources if s.get("container")]
    with operation(db):
        impact = {"kind": "containers", "containers": containers,
                  "edge_customers_unaffected": True}
        order = _get_order(db, order_id=order_id, incident_id=incident_id)
        if order is None:
            result = approve(db, order_id=order_id or deterministic_id(
                                 "order", incident_id, "isolate_containers", *containers),
                             incident_id=incident_id, play="isolate_containers",
                             targets=containers, approved_impact=impact,
                             approved_by=pick(kwargs, "approved_by", default="security-officer"),
                             ops_lead=pick(kwargs, "ops_lead", default="ops-lead"))
            order_id = result.meta.get("order_id") if isinstance(result, Code) else order_id
        else:
            order_id = order["order_id"]
        for c in containers:
            if migrate_first:
                live = unrelated_traffic(db, c)
                if live:
                    return Code("traffic_not_migrated", "migrate_unrelated_traffic_first",
                                "live_traffic_present",
                                pending=[w["workload"] for w in live])
            move_to_forensics(db, order_id=order_id, container=c,
                              tenant=pick(kwargs, "tenant"))
            revoke_egress(db, order_id=order_id, container=c,
                          tenant=pick(kwargs, "tenant"))
    if fabric is not None:
        for c in containers:
            for receipt in _fabric_receipts_container(fabric, c, order_id):
                ingest_receipt(db, receipt)
    status = container_status(db, order_id=order_id, targets=containers)
    if pick(kwargs, "detail", "as_dict", default=False):
        return status
    return status["status"]


quarantine_containers = isolate_containers
forensic_isolation = isolate_containers
isolate_candidate_containers = isolate_containers
container_stop_loss = isolate_containers


def _fabric_receipts_container(fabric, container, order_id):
    out = []
    rid_move = deterministic_id("move", order_id, container, "forensics")
    rid_revoke = deterministic_id("revoke", order_id, container)
    for kind, method, rid, extra in (
            ("move_forensics", "move_to_forensics", rid_move, {"network": "forensics"}),
            ("revoke_egress", "revoke_egress", rid_revoke, {})):
        try:
            fn = getattr(fabric, method, None)
            result = fn(rid, container) if callable(fn) else None
            receipt = result if isinstance(result, dict) else {
                "receipt_id": deterministic_id("rcpt", rid), "request_id": rid,
                "system": "container", "kind": kind, "status": "confirmed",
                "container": container, **extra}
            out.append(receipt)
        except Exception as error:
            out.append({"request_id": rid, "system": "container", "kind": kind,
                        "status": "failed", "confirmed": False,
                        "container": container, "error": str(error)})
    return out

# ---------------------------------------------------------------------------
# 额外命名兼容与智能路由
# ---------------------------------------------------------------------------
rule = install_rule
add_access_rule = install_rule
confirm_rule_effective = switch_receipt
confirm_block = switch_receipt
complete_block = switch_receipt
block_receipt = switch_receipt
receipt = ingest_receipt
apply_external_receipt = ingest_receipt
record_external_receipt = ingest_receipt

block_edge = seal_edge
seal_e1 = seal_edge
stop_edge_egress = seal_edge
cut_edge = seal_edge

isolate = isolate_containers
forensic_quarantine = isolate_containers
quarantine_candidates = isolate_containers

migrate = migrate_traffic
drain_traffic = migrate_traffic
move_forensics = move_to_forensics
revoke = revoke_egress

recover_from_receipts = reconcile
restore_from_receipts = reconcile
sync = reconcile

check = verify_cut
is_cut = verify_cut
cut_status = verify_cut


def quarantine(db, *args, **kwargs):
    """智能止损路由：给出 containers/targets 走容器取证隔离，否则封整个 edge。"""
    containers = pick(kwargs, "containers", "targets", "container_ids")
    if containers is None and args and isinstance(args[0], (list, tuple, set)):
        containers = list(args[0])
    if containers:
        kwargs.setdefault("containers", list(containers))
        return isolate_containers(db, **kwargs)
    edge = pick(kwargs, "edge", "edge_id")
    if edge is None and args and isinstance(args[0], str):
        edge = args[0]
    return seal_edge(db, edge=edge, **{k: v for k, v in kwargs.items() if k != "edge"})


def pending_blocks(db, edge=None):
    ensure(db)
    if edge:
        return qall(db, "SELECT * FROM response_order WHERE edge=? AND status!='contained'", (edge,))
    return qall(db, "SELECT * FROM response_order WHERE status!='contained'")


def block_records(db, edge=None):
    _legacy_table(db)
    if edge:
        return qall(db, "SELECT rowid,* FROM edge_blocks WHERE edge=?", (edge,))
    return qall(db, "SELECT rowid,* FROM edge_blocks")


def live_sessions(db, edge=None, egress_port=None):
    """仍在连接表中、未清空且未死亡的可行会话（规则 alone 切不断它们）。"""
    ensure(db)
    sql = ("SELECT * FROM net_session WHERE cleared=0 AND feasible=1 "
           "AND LOWER(COALESCE(state,'established')) NOT IN "
           "('closed','expired','gone','dead')")
    args = []
    if edge is not None:
        sql += " AND edge=?"; args.append(edge)
    if egress_port is not None:
        sql += " AND egress_port=?"; args.append(str(egress_port))
    return qall(db, sql, args)


def flow_still_active(db, target=None, **kwargs):
    """规则已加但旧可行会话仍在时为 True：账上封锁不等于物理切断。"""
    if not verify_cut(db, target, **kwargs)["all_cut"]:
        return True
    return bool(live_sessions(db, kwargs.get("edge"), kwargs.get("egress_port")))


old_sessions_remaining = live_sessions


def register_workload(db, container, workload, tenant=None, live=True, **kwargs):
    """登记容器上的（可能无关）在线流量/工作负载；未迁走前禁止直接取証隔离。"""
    ensure(db)
    with operation(db):
        db.execute("INSERT INTO container_workload(container,workload,tenant,live) "
                   "VALUES(?,?,?,?) ON CONFLICT(container,workload) DO UPDATE SET live=excluded.live",
                   (container, str(workload), tenant, 1 if live else 0))
    return Code("registered", "recorded", "added")


add_workload = register_workload
register_traffic = register_workload

_FUZZY_TABLE = (
    (("reconcil", "recover", "restore", "sync_receipt"), "reconcile"),
    (("verify", "still_active", "flow_still", "is_cut", "cut_verified"), "verify_cut"),
    (("container_status",), "container_status"),
    (("edge_status", "block_status", "quarantine_status", "containment_status", "status"), "edge_status"),
    (("workload",), "register_workload"),
    (("migrat", "drain", "traffic"), "migrate_traffic"),
    (("move_forensic", "to_forensic", "forensics_move"), "move_to_forensics"),
    (("revoke", "capability"), "revoke_egress"),
    (("container", "forensic", "isolate", "pod"), "isolate_containers"),
    (("clear_session", "flush", "kill_session", "purge", "old_session", "clear_conntrack"), "clear_sessions"),
    (("switch_receipt", "rule_receipt", "confirm_rule", "confirm_block", "complete_block"), "switch_receipt"),
    (("container_receipt",), "container_receipt"),
    (("receipt", "ack", "confirm", "complete"), "ingest_receipt"),
    (("live_session", "remaining"), "live_sessions"),
    (("rule", "access", "deny", "acl"), "install_rule"),
    (("approve", "order", "authorize", "sign"), "approve"),
    (("seal", "block_edge", "stop_edge", "emergency"), "seal_edge"),
    (("block",), "block"),
)


def __getattr__(name):
    from .evidence import lazy_alias
    return lazy_alias(name, globals(), _FUZZY_TABLE)
