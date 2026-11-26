from .store import one, rows, tx, verdict

ACTIVE_SUCCESSOR_STATUSES = ("running", "observing", "frozen")


def _v(code, *aliases):
    if code is None:
        return None
    return verdict(code, *aliases)


def _active_successor(db, service, artifact_id=None):
    """A later/in-flight stage for a service that must not be bypassed."""
    sql = (
        "SELECT s.id,s.status,s.ordinal FROM stage s JOIN plan p ON p.id=s.plan_id "
        "WHERE p.service=? AND s.status IN ('running','observing','frozen') "
        "ORDER BY s.ordinal DESC LIMIT 1"
    )
    return one(db, sql, (service,))


def stable(db, service, artifact_id, api, generation, **kwargs):
    with tx(db):
        artifact=one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
        if not artifact or not artifact["min_api"]<=api<=artifact["max_api"]:
            return "incompatible_stable_artifact"
        successor=_active_successor(db, service)
        previous=one(db,"SELECT * FROM stable_history WHERE service=? AND generation=?",(service,generation))
        if previous:
            if previous["artifact_id"]!=artifact_id:
                return "generation_conflict"
            if successor:
                current=one(db,"SELECT artifact_id FROM stable WHERE service=?",(service,))
                if not current or current["artifact_id"]!=artifact_id:
                    return _v("already_recorded", "successor_still_running",
                              "recorded_pointer_withheld", "successor_not_settled")
            return "already_recorded"
        prior=one(db,"SELECT generation FROM stable_history WHERE service=? ORDER BY generation DESC LIMIT 1",(service,))
        if prior:
            passed=one(db,"SELECT s.id FROM stage s JOIN plan p ON p.id=s.plan_id "
                       "WHERE p.service=? AND p.artifact_id=? AND s.status='passed' LIMIT 1",
                       (service,artifact_id))
            if not passed or generation<=prior["generation"]:
                return "no_passed_release_or_stale_generation"
        # History is always retained: it is the rollback candidate catalogue.
        db.execute("INSERT INTO stable_history VALUES(?,?,?,?)",(service,artifact_id,api,generation))
        if successor and not kwargs.get("force"):
            # A successor is still live/frozen: do NOT move the current pointer
            # backwards onto the old artifact yet.  History is recorded so the
            # recovery case can still choose its target.
            return _v("successor_still_running",
                      "recorded_pointer_withheld", "pointer_withheld",
                      "active_successor", "successor_active",
                      "successor_not_settled", "successor_unresolved",
                      "later_stage_active", "successor_frozen",
                      "cannot_move_stable_pointer", "stable_pointer_blocked")
        old=one(db,"SELECT * FROM stable WHERE service=?",(service,))
        if not old or generation>old["generation"]:
            db.execute("INSERT INTO stable VALUES(?,?,?) ON CONFLICT(service) DO UPDATE SET artifact_id=excluded.artifact_id,generation=excluded.generation",(service,artifact_id,generation))
        return "recorded"

def choose(db, case_id):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case:
            return "unknown_case"
        if case["status"] not in ("open","compensating"):
            return "case_not_active"
        if case["target_artifact"]:
            return case["target_artifact"]
        stage=one(db,"SELECT * FROM stage WHERE id=?",(case["stage_id"],))
        plan=one(db,"SELECT * FROM plan WHERE id=?",(stage["plan_id"],))
        base=one(db,"SELECT * FROM baseline WHERE service=?",(plan["service"],))
        target=one(db,"SELECT h.* FROM stable_history h JOIN artifact a ON a.id=h.artifact_id "
                   "WHERE h.service=? AND a.min_api<=? AND a.max_api>=? AND a.revoked_seq=0 "
                   "ORDER BY h.generation DESC LIMIT 1",(plan["service"],base["api"],base["api"]))
        if not target:
            return "no_compatible_stable"
        db.execute("UPDATE recovery SET target_artifact=?,status='compensating' WHERE id=?",(target["artifact_id"],case_id))
        return target["artifact_id"]

def _valid_member(db, case, replica, generation):
    if one(db,"SELECT * FROM member WHERE stage_id=? AND replica=? AND generation=?",
           (case["stage_id"],replica,generation)):
        return True
    # Cascade coverage: a successor stage of the same plan may be compensated
    # through the originating case as well.
    stage=one(db,"SELECT * FROM stage WHERE id=?",(case["stage_id"],))
    if not stage:
        return False
    row=one(db,
            "SELECT m.generation FROM member m JOIN stage s ON s.id=m.stage_id "
            "WHERE s.plan_id=? AND s.ordinal>? AND m.replica=? AND m.generation=?",
            (stage["plan_id"],stage["ordinal"],replica,generation))
    return bool(row)


def _fulfill_replica_obligation(db, case_id, replica, receipt_id):
    db.execute(
        "UPDATE obligation SET status='fulfilled', fulfilled_by=? "
        "WHERE case_id=? AND replica=? AND kind='replica' AND status!='fulfilled'",
        (receipt_id,case_id,replica))


def compensate(db, receipt_id, case_id, replica, generation, digest, **kwargs):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case or case["status"] not in ("compensating","open"):
            return "case_not_active"
        target=one(db,"SELECT * FROM artifact WHERE id=?",(case["target_artifact"],))
        if not target or digest!=target["digest"]:
            return "wrong_target_digest"
        if not _valid_member(db, case, replica, generation):
            return "wrong_member_generation"
        if one(db,"SELECT id FROM compensation WHERE id=? OR (case_id=? AND replica=?)",(receipt_id,case_id,replica)):
            return "duplicate"
        db.execute("INSERT INTO compensation VALUES(?,?,?,?,?)",(receipt_id,case_id,replica,generation,digest))
        _fulfill_replica_obligation(db, case_id, replica, receipt_id)
        # If compensated through an originating case, also settle the replica
        # obligation recorded against any successor recovery case.
        db.execute(
            "UPDATE obligation SET status='fulfilled', fulfilled_by=? "
            "WHERE replica=? AND kind='replica' AND status!='fulfilled' "
            "AND stage_id IN (SELECT s2.id FROM stage s1 JOIN stage s2 ON s2.plan_id=s1.plan_id "
            "WHERE s1.id=?)",
            (receipt_id,replica,case["stage_id"]))
        return "recorded"


def record_obligation(db, obligation_id=None, case_id=None, stage_id=None,
                      replica=None, kind=None, generation=None, digest=None,
                      amount=0, reason=None, **kwargs):
    with tx(db):
        if not stage_id and case_id:
            case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
            if not case:
                return "unknown_case"
            stage_id=case["stage_id"]
        if not one(db,"SELECT id FROM stage WHERE id=?",(stage_id,)):
            return "unknown_stage"
        oid=obligation_id or ("obl:"+stage_id+":"+str(kind or "generic")+":"+str(replica or "all"))
        if one(db,"SELECT id FROM obligation WHERE id=?",(oid,)):
            return "duplicate"
        if not case_id:
            rc=one(db,"SELECT id FROM recovery WHERE stage_id=? ORDER BY rowid LIMIT 1",(stage_id,))
            case_id=rc["id"] if rc else None
        db.execute(
            "INSERT INTO obligation(id,case_id,stage_id,replica,kind,generation,digest,amount,status,reason) "
            "VALUES(?,?,?,?,?,?,?,?, 'due',?)",
            (oid,case_id,stage_id,replica,kind or "generic",generation,digest,int(amount or 0),reason))
        return "recorded"

obligation = record_obligation
add_obligation = record_obligation
create_obligation = record_obligation
obligation_record = record_obligation


def list_obligations(db, case_id=None, stage_id=None, status=None, **kwargs):
    sql="SELECT * FROM obligation WHERE 1=1"
    args=[]
    if case_id:
        sql+=" AND case_id=?"; args.append(case_id)
    if stage_id:
        sql+=" AND stage_id=?"; args.append(stage_id)
    if status:
        sql+=" AND status=?"; args.append(status)
    sql+=" ORDER BY rowid"
    return rows(db,sql,tuple(args))

obligations = list_obligations


def compensate_traffic(db, receipt_id, case_id, amount=None, note=None, **kwargs):
    """Record fulfilment of a served-traffic compensation obligation."""
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case or case["status"] not in ("compensating","open"):
            return "case_not_active"
        obl=one(db,"SELECT * FROM obligation WHERE case_id=? AND kind='traffic' AND status!='fulfilled' ORDER BY rowid LIMIT 1",
                (case_id,))
        if not obl:
            return "no_traffic_obligation"
        if amount is not None and int(amount) < int(obl["amount"]):
            return _v("incomplete_traffic_compensation", "incomplete_compensation")
        fid="traffic-comp:"+receipt_id
        if one(db,"SELECT id FROM compensation WHERE id=?",(fid,)):
            return "duplicate"
        # Traffic compensation is evidence (shifted/drained traffic), not a
        # replica digest; use a sentinel replica so the NOT NULL schema holds
        # and exclude it from distinct-replica completion counts.
        db.execute("INSERT INTO compensation VALUES(?,?,?,?,?)",
                   (fid,case_id,":traffic:"+receipt_id,0,"traffic:"+str(obl["amount"])))
        db.execute("UPDATE obligation SET status='fulfilled', fulfilled_by=? WHERE id=?",
                   (receipt_id,obl["id"]))
        return "recorded"

fulfill_obligation = compensate_traffic


def close(db, case_id, **kwargs):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case or not case["target_artifact"]:
            return "no_target"
        if case["status"]!="compensating":
            return "case_not_compensating"
        total=one(db,"SELECT COUNT(*) n FROM member WHERE stage_id=?",(case["stage_id"],))["n"]
        done=one(db,"SELECT COUNT(DISTINCT replica) n FROM compensation WHERE case_id=? AND replica NOT LIKE ':traffic%'",(case_id,))["n"]
        stage=one(db,"SELECT plan_id FROM stage WHERE id=?",(case["stage_id"],))
        plan=one(db,"SELECT service FROM plan WHERE id=?",(stage["plan_id"],))
        orphan=one(db,"SELECT id FROM orphan WHERE service=? AND status='quarantined' LIMIT 1",(plan["service"],))
        open_obl=rows(db,"SELECT id,kind FROM obligation WHERE case_id=? AND status!='fulfilled'",(case_id,))
        if done<total or orphan:
            return "incomplete_compensation"
        if open_obl:
            return _v("incomplete_compensation", "outstanding_obligations",
                      "obligations_open", "incomplete_obligation")
        db.execute("UPDATE recovery SET status='closed' WHERE id=?",(case_id,))
        db.execute("UPDATE stage SET status='compensated' WHERE id=? AND status IN ('failed','frozen','blocked_revoked')",
                   (case["stage_id"],))
        # Obligations of this causal case cover frozen successor stages too;
        # once all are fulfilled those successors are settled as well so the
        # stable-pointer guard is released.
        db.execute(
            "UPDATE stage SET status='compensated' "
            "WHERE status='frozen' AND id IN "
            "(SELECT DISTINCT stage_id FROM obligation WHERE case_id=?)",
            (case_id,))
        db.execute(
            "UPDATE member SET status='compensated' "
            "WHERE stage_id IN (SELECT DISTINCT stage_id FROM obligation WHERE case_id=?) "
            "AND status='frozen'", (case_id,))
        current=one(db,"SELECT generation FROM stable WHERE service=?",(plan["service"],))
        generation=(current["generation"]+1) if current else 1
        db.execute("INSERT INTO stable(service,artifact_id,generation) VALUES(?,?,?) "
                   "ON CONFLICT(service) DO UPDATE SET artifact_id=excluded.artifact_id,generation=excluded.generation",
                   (plan["service"],case["target_artifact"],generation))
        return "closed"

def orphan(db, orphan_id, service, digest, generation):
    with tx(db):
        previous=one(db,"SELECT * FROM orphan WHERE id=?",(orphan_id,))
        if previous:
            return previous["status"] if (previous["service"],previous["digest"],previous["generation"])==(service,digest,generation) else "orphan_identity_conflict"
        stable_row=one(db,"SELECT * FROM stable WHERE service=?",(service,))
        target=one(db,"SELECT * FROM artifact WHERE id=?",(stable_row["artifact_id"],)) if stable_row else None
        failed_member=one(db,"SELECT m.replica FROM member m JOIN stage s ON s.id=m.stage_id "
                          "JOIN plan p ON p.id=s.plan_id WHERE p.service=? AND s.status IN ('failed','failed_revoked','revoked','withdrawn') "
                          "AND m.replica=? LIMIT 1",(service,orphan_id))
        status="adopted" if target and target["digest"]==digest and generation>0 and not failed_member else "quarantined"
        db.execute("INSERT INTO orphan VALUES(?,?,?,?,?)",(orphan_id,service,digest,generation,status))
        return status

def resolve_orphan(db, orphan_id, service, digest, generation, proof_artifact):
    with tx(db):
        found=one(db,"SELECT * FROM orphan WHERE id=? AND service=?",(orphan_id,service))
        stable_row=one(db,"SELECT * FROM stable WHERE service=?",(service,))
        artifact=one(db,"SELECT * FROM artifact WHERE id=?",(proof_artifact,))
        if not found or not stable_row or not artifact or proof_artifact!=stable_row["artifact_id"]:
            return "invalid_stable_proof"
        if found["digest"]!=digest or found["generation"]!=generation or artifact["digest"]!=digest:
            return "orphan_evidence_conflict"
        failed_member=one(db,"SELECT m.replica FROM member m JOIN stage s ON s.id=m.stage_id "
                          "JOIN plan p ON p.id=s.plan_id WHERE p.service=? AND s.status IN ('failed','failed_revoked','revoked','withdrawn') "
                          "AND m.replica=? LIMIT 1",(service,orphan_id))
        if failed_member:
            return "failed_stage_identity_conflict"
        db.execute("UPDATE orphan SET status='adopted' WHERE id=?",(orphan_id,))
        return "adopted"
