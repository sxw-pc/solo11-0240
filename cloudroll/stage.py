from .store import one, rows, tx
from .artifact import client_eligibility

def start(db, stage_id, plan_id, members, start_ts, end_ts, max_fail=0, ordinal=1):
    with tx(db):
        plan=one(db,"SELECT * FROM plan WHERE id=?",(plan_id,))
        if not plan or plan["status"]!="locked":
            return "plan_not_locked"
        baseline=one(db,"SELECT generation FROM baseline WHERE service=?",(plan["service"],))
        artifact=one(db,"SELECT revoked_seq FROM artifact WHERE id=?",(plan["artifact_id"],))
        if not baseline or baseline["generation"]!=plan["baseline_gen"] or artifact["revoked_seq"]:
            return "baseline_or_artifact_changed"
        if client_eligibility(db,plan["service"],plan["artifact_id"],plan["end_ts"])!="eligible":
            return "client_contract_no_longer_covered"
        if start_ts<plan["start_ts"] or end_ts>plan["end_ts"] or start_ts>=end_ts:
            return "stage_outside_release_window"
        if not members or len({m["replica"] for m in members})!=len(members):
            return "invalid_fixed_members"
        if max_fail<0 or max_fail>=len(members):
            return "invalid_failure_budget"
        if ordinal<1 or ordinal>plan["stage_count"]:
            return "invalid_stage_ordinal"
        if one(db,"SELECT id FROM stage WHERE plan_id=? AND ordinal=?",(plan_id,ordinal)):
            return "ordinal_already_started"
        if ordinal>1:
            previous=one(db,"SELECT status FROM stage WHERE plan_id=? AND ordinal=?",(plan_id,ordinal-1))
            if not previous or previous["status"]!="passed":
                return "previous_stage_not_passed"
        if one(db,"SELECT id FROM stage WHERE id=?",(stage_id,)):
            return "already_started"
        db.execute("INSERT INTO stage VALUES(?,?,?,?,?,?,?)",(stage_id,plan_id,ordinal,start_ts,end_ts,max_fail,"running"))
        for member in members:
            db.execute("INSERT INTO member VALUES(?,?,?)",(stage_id,member["replica"],member["generation"]))
        return "started"

def receipt(db, receipt_id, stage_id, replica, generation, digest):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        m=one(db,"SELECT * FROM member WHERE stage_id=? AND replica=?",(stage_id,replica))
        if not s or not m:
            return "not_a_fixed_member"
        if s["status"]!="running":
            return "stage_not_running"
        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
        if generation!=m["generation"] or digest!=a["digest"]:
            return "wrong_identity_or_digest"
        if one(db,"SELECT id FROM receipt WHERE id=?",(receipt_id,)):
            return "duplicate"
        if one(db,"SELECT id FROM receipt WHERE stage_id=? AND replica=?",(stage_id,replica)):
            return "already_acknowledged"
        db.execute("INSERT INTO receipt VALUES(?,?,?,?,?)",(receipt_id,stage_id,replica,generation,digest))
        return "recorded"

def sample(db, sample_id, stage_id, replica, at, digest, healthy):
    with tx(db):
        if not one(db,"SELECT id FROM stage WHERE id=?",(stage_id,)):
            return "unknown_stage"
        if not one(db,"SELECT replica FROM member WHERE stage_id=? AND replica=?",(stage_id,replica)):
            return "not_a_fixed_member"
        if one(db,"SELECT id FROM sample WHERE id=?",(sample_id,)):
            return "duplicate"
        db.execute("INSERT INTO sample VALUES(?,?,?,?,?,?)",(sample_id,stage_id,replica,at,digest,int(healthy)))
        return "recorded"

def decide(db, stage_id, at):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        if not s or s["status"]!="running":
            return "not_running"
        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
        if p["status"]!="locked" or a["revoked_seq"]:
            db.execute("UPDATE stage SET status='blocked_revoked' WHERE id=?",(stage_id,))
            return "blocked_revoked"
        members=rows(db,"SELECT * FROM member WHERE stage_id=?",(stage_id,))
        missing=[]
        failed=0
        for m in members:
            r=one(db,"SELECT id FROM receipt WHERE stage_id=? AND replica=? AND generation=? AND digest=?",(stage_id,m["replica"],m["generation"],a["digest"]))
            if not r:
                missing.append(m["replica"])
            samples=rows(db,"SELECT * FROM sample WHERE stage_id=? AND replica=? AND at>=? AND at<=? AND digest=? ORDER BY at DESC,id DESC",(stage_id,m["replica"],s["start_ts"],s["end_ts"],a["digest"]))
            if r and samples and not samples[0]["healthy"]:
                failed+=1
            if r and not samples:
                missing.append(m["replica"]+":health")
        if failed>s["max_fail"] or (at>s["end_ts"] and missing):
            db.execute("UPDATE stage SET status='failed' WHERE id=?",(stage_id,))
            db.execute("UPDATE plan SET status='failed' WHERE id=?",(p["id"],))
            db.execute("INSERT OR IGNORE INTO recovery VALUES(?,?,?,?)",("rec-"+stage_id,stage_id,None,"open"))
            return "failed:"+",".join(missing)
        if missing:
            return "waiting:"+",".join(missing)
        db.execute("UPDATE stage SET status='passed' WHERE id=?",(stage_id,))
        if s["ordinal"]==p["stage_count"]:
            db.execute("UPDATE plan SET status='passed' WHERE id=?",(p["id"],))
        return "passed"


# ---------------------------------------------------------------------------
# 事件止损“阶段门”：候选来源固定后，必须收齐外部回执并核验切断，才能封卷。
# 与发布阶段同样的原则：成员一经固定，晚到证据不改分母；回执不齐不算完成。
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402
from . import edge_quarantine as _eq  # noqa: E402
from . import flow_capture as _fc  # noqa: E402
from .evidence import Code as _Code, ensure as _ensure, q1 as _q1  # noqa: E402


def open_incident(db, incident_id, edge=None, egress_port=None, play=None,
                  candidates=None, containers=None, approved_by="security-officer",
                  ops_lead="ops-lead", impact=None, **kwargs):
    """固定可疑事件与获批处置做法。候选来源在此固定，后续证据只缩小责任、不改止损覆盖。"""
    _ensure(db)
    if candidates is None:
        candidates = containers
    if candidates is None and edge is not None:
        sources = _fc.candidate_sources(db, edge=edge, egress_port=egress_port)
        candidates = [s["container"] for s in sources if s.get("container")]
    if play is None:
        play = "seal_edge" if edge else "isolate_containers"
    order_id = kwargs.pop("order_id", None) or ("order:" + str(incident_id))
    result = _eq.approve(db, order_id=order_id, incident_id=incident_id, play=play,
                         edge=edge, targets=candidates, approved_impact=impact,
                         approved_by=approved_by, ops_lead=ops_lead, **kwargs)
    return {"incident_id": incident_id, "order_id": order_id, "play": play,
            "edge": edge, "candidates": candidates or [],
            "status": str(result) if isinstance(result, _Code) else result}


def incident_receipt(db, receipt_id=None, request_id=None, kind=None, status="confirmed",
                     system="switch", **kwargs):
    """登记交换机/容器外部幂等回执（等价 edge_quarantine.ingest_receipt）。"""
    return _eq.ingest_receipt(db, {"receipt_id": receipt_id, "request_id": request_id,
                                   "kind": kind, "status": status, "system": system, **kwargs})


response_receipt = incident_receipt
containment_receipt = incident_receipt


def execute_response(db, incident_id, fabric=None, **kwargs):
    """按已批准做法执行处置；提供 fabric 时同步取得并保存外部回执。"""
    order = _q1(db, "SELECT * FROM response_order WHERE incident_id=? ORDER BY rowid DESC LIMIT 1",
                (incident_id,))
    if order is None:
        return _Code("no_approved_response", "order_missing", "not_authorized")
    if order["play"] == "seal_edge":
        status = _eq.seal_edge(db, order_id=order["order_id"], edge=order["edge"],
                               incident_id=incident_id, fabric=fabric, **kwargs)
        detail = _eq.edge_status(db, order["order_id"])
    else:
        targets = _json.loads(order["targets"] or "[]")
        status = _eq.isolate_containers(db, order_id=order["order_id"],
                                        containers=targets, incident_id=incident_id,
                                        fabric=fabric, **kwargs)
        detail = _eq.container_status(db, order["order_id"], targets=targets)
    verification = _eq.verify_cut(db, incident_id)
    return {"incident_id": incident_id, "order_id": order["order_id"],
            "play": order["play"], "status": status, "detail": detail,
            "verification": verification}


def decide_incident(db, incident_id, **kwargs):
    """止损封卷裁决：所有相容历史均确认被切，且回执齐全，才返回 contained。"""
    order = _q1(db, "SELECT * FROM response_order WHERE incident_id=? ORDER BY rowid DESC LIMIT 1",
                (incident_id,))
    if order is None:
        return _Code("no_approved_response", "unknown_incident")
    verification = _eq.verify_cut(db, incident_id)
    if verification["all_cut"]:
        return _Code("contained", "blocked", "sealed", "complete", "verified")
    pending = [h["history_id"] for h in verification["uncut"]]
    return _Code("waiting:receipts", "pending", "incomplete", "not_contained",
                 uncut=pending)


incident_stage = open_incident
response_stage = open_incident
open_response = open_incident
contain_incident = execute_response
run_response = execute_response
decide_response = decide_incident
