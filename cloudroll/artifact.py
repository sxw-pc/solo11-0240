from .store import event, one, rows, tx
from .privacy_release import digest_hex

def baseline(db, service, api, generation):
    with tx(db):
        old=one(db,"SELECT * FROM baseline WHERE service=?",(service,))
        if old and generation<=old["generation"]:
            return "stale_baseline"
        db.execute("INSERT INTO baseline VALUES(?,?,?) ON CONFLICT(service) DO UPDATE SET api=excluded.api,generation=excluded.generation",(service,api,generation))
        return "accepted"

def register(db, artifact_id, digest, min_api, max_api):
    with tx(db):
        if min_api>max_api:
            return "invalid_range"
        db.execute("INSERT INTO artifact(id,digest,min_api,max_api) VALUES(?,?,?,?)",(artifact_id,digest,min_api,max_api))
        return "accepted"

def contract(db, artifact_id, min_protocol, max_protocol):
    with tx(db):
        db.execute("INSERT INTO client_contract VALUES(?,?,?) ON CONFLICT(artifact_id) DO UPDATE SET min_protocol=excluded.min_protocol,max_protocol=excluded.max_protocol",(artifact_id,min_protocol,max_protocol))
        return "accepted"

def population(db, service, protocol, count):
    with tx(db):
        previous=one(db,"SELECT COALESCE(MAX(revision_no),0) AS n FROM population_revision WHERE service=? AND protocol=?",(service,protocol))
        revision_no=int(previous["n"])+1
        population_hash=digest_hex({"service":service,"protocol":protocol,"count":count,"revision_no":revision_no})
        db.execute("INSERT INTO clients VALUES(?,?,?) ON CONFLICT(service,protocol) DO UPDATE SET population=excluded.population",(service,protocol,count))
        db.execute("INSERT INTO population_revision(service,protocol,population,revision_no,population_hash) VALUES(?,?,?,?,?)",
                   (service,protocol,count,revision_no,population_hash))
        revision_seq=db.execute("SELECT last_insert_rowid() AS seq").fetchone()[0]
        db.execute("INSERT INTO population_history(revision_seq,service,protocol,count,population,revision_no,version,population_hash) VALUES(?,?,?,?,?,?,?,?)",
                   (revision_seq,service,protocol,count,count,revision_no,revision_no,population_hash))
        return "accepted"

def proxy(db, commitment_id, service, protocol, until_ts):
    with tx(db):
        db.execute("INSERT INTO proxy_commitment VALUES(?,?,?,?)",(commitment_id,service,protocol,until_ts))
        return "accepted"

def client_eligibility(db, service, artifact_id, end_ts):
    contract=one(db,"SELECT * FROM client_contract WHERE artifact_id=?",(artifact_id,))
    if not contract:
        return "missing_client_contract"
    for c in rows(db,"SELECT * FROM clients WHERE service=? AND population>0",(service,)):
        if contract["min_protocol"]<=c["protocol"]<=contract["max_protocol"]:
            continue
        if not one(db,"SELECT id FROM proxy_commitment WHERE service=? AND protocol=? AND until_ts>=?",(service,c["protocol"],end_ts)):
            return "unsupported_active_clients"
    return "eligible"

def plan(db, event_id, plan_id, service, artifact_id, start_ts, end_ts, stage_count=1):
    data=dict(plan_id=plan_id,service=service,artifact_id=artifact_id,start_ts=start_ts,end_ts=end_ts,stage_count=stage_count)
    with tx(db):
        old=one(db,"SELECT * FROM events WHERE id=?",(event_id,))
        if old:
            verdict=event(db,event_id,"artifact.plan",data,old["verdict"])
            from .external_attest import snapshot_plan
            snapshot_plan(db,event_id,data,verdict)
            return verdict
        if start_ts>=end_ts:
            verdict="invalid_release_window"
        elif stage_count<1:
            verdict="invalid_stage_count"
        elif one(db,"SELECT id FROM plan WHERE id=?",(plan_id,)):
            verdict="plan_identity_conflict"
        else:
            a=one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
            b=one(db,"SELECT * FROM baseline WHERE service=?",(service,))
            if not a or not b or a["revoked_seq"] or not a["min_api"]<=b["api"]<=a["max_api"]:
                verdict="incompatible_or_revoked"
            else:
                client=client_eligibility(db,service,artifact_id,end_ts)
                if client!="eligible":
                    verdict=client
                else:
                    overlap=one(db,"SELECT id FROM plan WHERE service=? AND status='locked' AND start_ts<? AND end_ts>?",(service,end_ts,start_ts))
                    if overlap:
                        verdict="window_conflict:"+overlap["id"]
                    else:
                        db.execute("INSERT INTO plan VALUES(?,?,?,?,?,?,?,?)",(plan_id,service,artifact_id,start_ts,end_ts,b["generation"],stage_count,"locked"))
                        verdict="locked"
        stored=event(db,event_id,"artifact.plan",data,verdict)
        from .external_attest import snapshot_plan
        snapshot_plan(db,event_id,data,stored)
        return stored

def revoke(db, event_id, artifact_id, seq):
    data=dict(artifact_id=artifact_id,seq=seq)
    with tx(db):
        a=one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
        if not a:
            return event(db,event_id,"artifact.revoke",data,"unknown_artifact")
        if seq<=a["revoked_seq"]:
            return event(db,event_id,"artifact.revoke",data,"stale_revocation")
        db.execute("UPDATE artifact SET revoked_seq=? WHERE id=?",(seq,artifact_id))
        db.execute("UPDATE plan SET status='blocked_revoked' WHERE artifact_id=? AND status='locked'",(artifact_id,))
        return event(db,event_id,"artifact.revoke",data,"revoked")
