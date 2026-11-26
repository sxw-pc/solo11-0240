import argparse
import json
from pathlib import Path
from . import artifact, stage, recovery, writes
from .store import open_db, report, one, rows, tx, wrap_result
from . import dispatch

COMMANDS={f"artifact.{name}":getattr(artifact,name) for name in ["baseline","register","contract","population","proxy","plan","revoke"]}
COMMANDS.update({f"stage.{name}":getattr(stage,name) for name in ["start","receipt","sample","decide"]})
COMMANDS.update({f"recovery.{name}":getattr(recovery,name) for name in ["stable","choose","compensate","close","orphan","resolve_orphan"]})

# Richer canonical commands (also reachable through the dispatcher aliases).
COMMANDS.update({
    "artifact.format": artifact.register_format,
    "artifact.register_format": artifact.register_format,
    "artifact.bridge": artifact.register_bridge,
    "artifact.format_bridge": artifact.register_bridge,
    "artifact.bridge_proof": artifact.bridge_proof,
    "artifact.proxy_path": artifact.proxy_path,
    "stage.deploy": stage.deploy,
    "stage.lease": stage.lease,
    "stage.policy": stage.policy,
    "stage.link_down": stage.link_down,
    "stage.link_up": stage.link_up,
    "stage.routing": stage.routing,
    "stage.route": stage.routing,
    "write.submit": writes.submit_write,
    "write.stage": writes.stage_write,
    "write.ack": writes.ack_write,
    "write.probe": writes.probe_commit,
    "write.recover": writes.probe_commit,
    "write.replicate": writes.replicate_write,
    "write.list": writes.list_writes,
    "recovery.region_stable": recovery.region_stable,
    "recovery.reconcile": recovery.reconcile,
    "recovery.switch_pointer": recovery.switch_pointer,
})


def _resolve(name):
    if name in COMMANDS:
        return COMMANDS[name]
    canonical = dispatch.resolve(name)
    if canonical and canonical in dispatch.REGISTRY:
        module_name, function_name = dispatch.REGISTRY[canonical]
        return dispatch._h(module_name, function_name)
    return None


def apply_command(db, name, args, request_id):
    handler = _resolve(name)
    if handler is None:
        raise ValueError("unknown operation " + name)
    with tx(db):
        old=one(db,"SELECT * FROM command_events WHERE request_id=?",(request_id,))
        canonical=json.dumps(args,sort_keys=True,ensure_ascii=False,default=str)
        if old:
            if old["kind"]!=name or old["payload"]!=canonical:
                raise ValueError("request identity reused with different input")
            return wrap_result(json.loads(old["result"]))
        if name in COMMANDS:
            result=COMMANDS[name](db,**args)
        else:
            result=dispatch.call_op(name,db,(),args)
        db.execute("INSERT INTO command_events(request_id,kind,payload,result) VALUES(?,?,?,?)",
                   (request_id,name,canonical,json.dumps(result,ensure_ascii=False,default=str)))
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
    # Canonical table -> compatibility names a caller may query/tamper.
    alias_names = {}
    for alias, canonical in getattr(__import__("cloudroll.store", fromlist=["TABLE_ALIASES"]),
                                    "TABLE_ALIASES", {}).items():
        alias_names.setdefault(canonical, []).append(alias)
    for table in report(db):
        actual=rows(db,"SELECT * FROM "+table+" ORDER BY rowid")
        replay=rows(rebuilt,"SELECT * FROM "+table+" ORDER BY rowid")
        if actual!=replay:
            mismatch={"table":table,"actual":len(actual),"replayed":len(replay)}
            mismatches.append(mismatch)
            for alias in alias_names.get(table, []):
                mismatches.append({"table":alias,"canonical_table":table,
                                   "actual":len(actual),"replayed":len(replay)})
    rebuilt.close()
    return {"event_count":len(events),"verified":not mismatches,"mismatches":mismatches}

def run(db_path,fixture,subsystem=None):
    db=open_db(db_path)
    result=[]
    for index,action in enumerate(json.loads(Path(fixture).read_text(encoding="utf8"))["actions"]):
        name=action["op"]
        request_id=action.get("request_id",f"{Path(fixture).stem}:{index}:{name}")
        result.append({"op":name,"result":apply_command(db,name,action.get("args",{}),request_id)})
    if subsystem and subsystem!="all" and not any(x["op"].startswith(subsystem+".") for x in result):
        raise ValueError("fixture has no "+subsystem+" operation")
    output={"results":result,"state":report(db),"audit":audit(db)}
    db.close()
    return output

def main():
    p=argparse.ArgumentParser()
    p.add_argument("subsystem")
    p.add_argument("fixture")
    p.add_argument("--db",default="cloudroll.sqlite")
    a=p.parse_args()
    known={"artifact","stage","recovery","all","region","write","bridge","federation","topology","proxy"}
    subsystem = a.subsystem if a.subsystem in known else None
    print(json.dumps(run(a.db,a.fixture,subsystem),ensure_ascii=False,indent=2,default=str))

if __name__=="__main__": main()
