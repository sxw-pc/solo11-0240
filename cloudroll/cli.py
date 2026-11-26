import argparse
import json
from pathlib import Path
from . import artifact, stage, recovery, provenance, signature, transparency
from .store import open_db, report, one, rows, tx

COMMANDS={f"artifact.{name}":getattr(artifact,name) for name in ["baseline","register","contract","population","proxy","plan","revoke","client_eligibility"]}
COMMANDS.update({f"stage.{name}":getattr(stage,name) for name in ["start","receipt","sample","decide"]})
COMMANDS.update({f"recovery.{name}":getattr(recovery,name) for name in ["stable","choose","compensate","close","orphan","resolve_orphan"]})
COMMANDS.update({f"provenance.{name}":getattr(provenance,name) for name in [
    "build","seal","cross_sign","attest","publish","withdraw",
    "quarantine_build","clean","affected","containment_report","source_digest_for_plan",
    "seal_record","build_record","artifact_for_build","refresh_seal","independent_attestation",
    "cleanup_record","pending_cleanup","mark_seal_contested","unmark_contested",
    "supersede_source_plans","attach_log"]})
COMMANDS.update({f"signature.{name}":getattr(signature,name) for name in [
    "register_key","authorize","key_status","revoke_key","put_signature",
    "make_signature","rescan","sign_head","sign_key_revocation",
    "get_key","scope_authorized","signature_page","authority_at"]})
COMMANDS.update({f"transparency.{name}":getattr(transparency,name) for name in [
    "register_witness","submit_head","anchor","consistency","trusted_head",
    "log_status","merkle_root","consistency_path","entry_in_trusted_head",
    "conflicts","key_contested","verify_consistency"]})

def apply_command(db, name, args, request_id):
    if name not in COMMANDS:
        raise ValueError("unknown operation " + name)
    with tx(db):
        old=one(db,"SELECT * FROM command_events WHERE request_id=?",(request_id,))
        canonical=json.dumps(args,sort_keys=True,ensure_ascii=False)
        if old:
            if old["kind"]!=name or old["payload"]!=canonical:
                raise ValueError("request identity reused with different input")
            return json.loads(old["result"])
        result=COMMANDS[name](db,**args)
        db.execute("INSERT INTO command_events(request_id,kind,payload,result) VALUES(?,?,?,?)",
                   (request_id,name,canonical,json.dumps(result,ensure_ascii=False)))
        return result

def audit(db):
    rebuilt=open_db(":memory:")
    mismatches=[]
    events=rows(db,"SELECT * FROM command_events ORDER BY seq")
    for event in events:
        try:
            result=apply_command(rebuilt,event["kind"],json.loads(event["payload"]),event["request_id"])
            if result!=json.loads(event["result"]):
                mismatches.append({"event":event["seq"],"reason":"result differs on replay"})
        except Exception as error:
            mismatches.append({"event":event["seq"],"reason":str(error)})
    for table in report(db):
        actual=rows(db,"SELECT * FROM "+table+" ORDER BY rowid")
        replay=rows(rebuilt,"SELECT * FROM "+table+" ORDER BY rowid")
        if actual!=replay:
            mismatches.append({"table":table,"actual":len(actual),"replayed":len(replay)})
    rebuilt.close()
    return {"event_count":len(events),"verified":not mismatches,"mismatches":mismatches}

def run(db_path,fixture,subsystem=None):
    db=open_db(db_path)
    result=[]
    for index,action in enumerate(json.loads(Path(fixture).read_text(encoding="utf8"))["actions"]):
        name=action["op"]
        request_id=action.get("request_id",f"{Path(fixture).stem}:{index}:{name}")
        result.append({"op":name,"result":apply_command(db,name,action.get("args",{}),request_id)})
    if subsystem and not any(x["op"].startswith(subsystem+".") for x in result):
        raise ValueError("fixture has no "+subsystem+" operation")
    output={"results":result,"state":report(db),"audit":audit(db)}
    db.close()
    return output

def main():
    p=argparse.ArgumentParser()
    p.add_argument("subsystem",choices=["artifact","stage","recovery","provenance","signature","transparency","all"])
    p.add_argument("fixture")
    p.add_argument("--db",default="cloudroll.sqlite")
    a=p.parse_args()
    print(json.dumps(run(a.db,a.fixture,None if a.subsystem=="all" else a.subsystem),ensure_ascii=False,indent=2))

if __name__=="__main__": main()
