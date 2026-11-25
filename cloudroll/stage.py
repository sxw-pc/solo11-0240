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
