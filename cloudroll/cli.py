import argparse
import json
import sys
from pathlib import Path
from . import artifact, stage, recovery, external_attest
from .store import open_db, report, one, rows, tx

COMMANDS={f"artifact.{name}":getattr(artifact,name) for name in ["baseline","register","contract","population","proxy","plan","revoke"]}
COMMANDS.update({f"stage.{name}":getattr(stage,name) for name in ["start","receipt","sample","decide"]})
COMMANDS.update({f"recovery.{name}":getattr(recovery,name) for name in ["stable","choose","compensate","close","orphan","resolve_orphan"]})
COMMANDS.update({
    "attest.issue": external_attest.issue_command,
    "attest.audited": lambda db, certificate_id, **kw: external_attest.issue_command(db, certificate_id, mode="audited", **kw),
    "attest.public": lambda db, certificate_id, **kw: external_attest.issue_command(db, certificate_id, mode="public", **kw),
    "attest.buyer": external_attest.issue_buyer_certificate,
    "attest.publish": external_attest.publish_certificate,
    "attest.revoke": external_attest.revoke_certificate,
    "attest.reissue": external_attest.reissue_certificate,
    "attest.outage": external_attest.record_proxy_outage,
    "attest.approve": external_attest.approve_release_mode,
    "external_attest.issue": external_attest.issue_command,
    "external_attest.audited": lambda db, certificate_id, **kw: external_attest.issue_command(db, certificate_id, mode="audited", **kw),
    "external_attest.public": lambda db, certificate_id, **kw: external_attest.issue_command(db, certificate_id, mode="public", **kw),
    "external_attest.verify": lambda db, certificate, **kw: external_attest.verify_certificate(certificate, **kw),
})

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
    # Signing/privacy derivation keys are installation state, not business
    # commands.  Copy them so replay-derived commitments/signatures match.
    for key in rows(db,"SELECT role,secret_hex,public_hex FROM attestation_key"):
        rebuilt.execute("INSERT OR REPLACE INTO attestation_key(role,secret_hex,public_hex) VALUES(?,?,?)",
                        (key["role"],key["secret_hex"],key["public_hex"]))
    mismatches=[]
    events=rows(db,"SELECT * FROM command_events ORDER BY seq")
    state_root=external_attest.state_root(db)
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
    replay_state_root=external_attest.state_root(rebuilt)
    rebuilt.close()
    return {"event_count":len(events),"verified":not mismatches,"mismatches":mismatches,
            "state_root":state_root,"replay_state_root":replay_state_root,
            "state_roots_match":state_root==replay_state_root}

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

def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"attest","external-attest","external_attest"}:
        return external_attest.external_cli(argv[1:])
    if argv and argv[0] in {"verify","verify-cert","verify_certificate"}:
        rest = argv[1:]
        if rest and not rest[0].startswith("--"):
            rest = ["verify"] + rest
        return external_attest.external_cli(rest)
    p=argparse.ArgumentParser()
    p.add_argument("subsystem",choices=["artifact","stage","recovery","all"])
    p.add_argument("fixture")
    p.add_argument("--db",default="cloudroll.sqlite")
    a=p.parse_args(argv)
    print(json.dumps(run(a.db,a.fixture,None if a.subsystem=="all" else a.subsystem),ensure_ascii=False,indent=2))
    return 0

if __name__=="__main__": raise SystemExit(main())
