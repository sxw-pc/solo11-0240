from .store import one, rows, tx

def stable(db, service, artifact_id, api, generation):
    with tx(db):
        artifact=one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
        if not artifact or not artifact["min_api"]<=api<=artifact["max_api"]:
            return "incompatible_stable_artifact"
        previous=one(db,"SELECT * FROM stable_history WHERE service=? AND generation=?",(service,generation))
        if previous:
            return "already_recorded" if previous["artifact_id"]==artifact_id else "generation_conflict"
        prior=one(db,"SELECT generation FROM stable_history WHERE service=? ORDER BY generation DESC LIMIT 1",(service,))
        if prior:
            passed=one(db,"SELECT s.id FROM stage s JOIN plan p ON p.id=s.plan_id "
                       "WHERE p.service=? AND p.artifact_id=? AND s.status='passed' LIMIT 1",
                       (service,artifact_id))
            if not passed or generation<=prior["generation"]:
                return "no_passed_release_or_stale_generation"
        db.execute("INSERT INTO stable_history VALUES(?,?,?,?)",(service,artifact_id,api,generation))
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

def compensate(db, receipt_id, case_id, replica, generation, digest):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case or case["status"] not in ("compensating","open"):
            return "case_not_active"
        target=one(db,"SELECT * FROM artifact WHERE id=?",(case["target_artifact"],))
        if not target or digest!=target["digest"]:
            return "wrong_target_digest"
        member=one(db,"SELECT * FROM member WHERE stage_id=? AND replica=?",(case["stage_id"],replica))
        if not member or generation!=member["generation"]:
            return "wrong_member_generation"
        if one(db,"SELECT id FROM compensation WHERE id=? OR (case_id=? AND replica=?)",(receipt_id,case_id,replica)):
            return "duplicate"
        db.execute("INSERT INTO compensation VALUES(?,?,?,?,?)",(receipt_id,case_id,replica,generation,digest))
        return "recorded"

def close(db, case_id):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case or not case["target_artifact"]:
            return "no_target"
        if case["status"]!="compensating":
            return "case_not_compensating"
        total=one(db,"SELECT COUNT(*) n FROM member WHERE stage_id=?",(case["stage_id"],))["n"]
        done=one(db,"SELECT COUNT(DISTINCT replica) n FROM compensation WHERE case_id=?",(case_id,))["n"]
        stage=one(db,"SELECT plan_id FROM stage WHERE id=?",(case["stage_id"],))
        plan=one(db,"SELECT service FROM plan WHERE id=?",(stage["plan_id"],))
        orphan=one(db,"SELECT id FROM orphan WHERE service=? AND status='quarantined' LIMIT 1",(plan["service"],))
        if done<total or orphan:
            return "incomplete_compensation"
        db.execute("UPDATE recovery SET status='closed' WHERE id=?",(case_id,))
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
                          "JOIN plan p ON p.id=s.plan_id WHERE p.service=? AND s.status='failed' "
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
                          "JOIN plan p ON p.id=s.plan_id WHERE p.service=? AND s.status='failed' "
                          "AND m.replica=? LIMIT 1",(service,orphan_id))
        if failed_member:
            return "failed_stage_identity_conflict"
        db.execute("UPDATE orphan SET status='adopted' WHERE id=?",(orphan_id,))
        return "adopted"
