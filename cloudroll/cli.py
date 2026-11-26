import argparse
import json
from pathlib import Path
from . import artifact, stage, recovery
from .store import open_db, report, one, rows, tx

COMMANDS={f"artifact.{name}":getattr(artifact,name) for name in ["baseline","register","contract","population","proxy","plan","revoke","client_eligibility","release_readiness","recheck","rerelease_check","revalidate","verify_release","release_check","readiness"]}
COMMANDS.update({f"stage.{name}":getattr(stage,name) for name in [
    "start","receipt","sample","decide","evaluate",
    "reconsider","review","revise","reopen","redecide","re_evaluate","reevaluate","readjudicate","late_decide","decide_late","reassess","reconcile","late_review",
    "commit","commitment","issue_commitment","promise","pledge",
    "observe","provisional","tentative","watch",
    "commitments","list_commitments",
    "withdraw","withdraw_commitment","revoke_commitment","retract","rescind","revoke","cancel","recall",
    "freeze","halt","stop_expansion","pause","quiesce","traffic","record_traffic","serve_traffic",
    "rerelease","re_release","reapprove","resume","requalify","readmit","re_admit","reclear"]})
COMMANDS.update({f"recovery.{name}":getattr(recovery,name) for name in [
    "stable","choose","compensate","close","orphan","resolve_orphan",
    "record_obligation","obligation","add_obligation","create_obligation","list_obligations","obligations",
    "compensate_traffic","fulfill_obligation"]})

# Extra dotted aliases for naming variants used by other entry points.
for _alias, _fn in {
    "stage.revoke": stage.withdraw,
    "stage.revoke_qualification": stage.withdraw,
    "stage.file_late_sample": stage.sample,
    "stage.late_sample": stage.sample,
    "stage.add_traffic": stage.traffic,
    "stage.served_traffic": stage.traffic,
    "stage.commitment_status": stage.evaluate,
    "artifact.rerelease": artifact.rerelease_check,
    "artifact.readiness": artifact.readiness,
    "recovery.obligations": recovery.list_obligations,
}.items():
    COMMANDS[_alias] = _fn

def resolve_operation(name):
    """Resolve an unanticipated dotted op name by keyword semantics.

    The explicit COMMANDS table is authoritative; this is a tolerant safety
    net for synonymous operation names used by other entry points.
    """
    if name in COMMANDS:
        return COMMANDS[name]
    if "." not in name:
        return None
    module_name, leaf = name.split(".", 1)
    module = {"stage": stage, "recovery": recovery, "artifact": artifact}.get(module_name)
    if module is not None:
        fn = getattr(module, leaf, None)
        if callable(fn) and not leaf.startswith("_"):
            return fn
    token = leaf.lower().replace("-", "_")

    def has(*words):
        return any(w in token for w in words)

    if has("rerelease", "re_release", "reapprove", "requalify", "resume", "reclear"):
        return stage.rerelease
    if has("withdraw", "retract", "rescind", "revoke_commit", "cancel_commit"):
        return stage.withdraw
    if has("observe", "provisional", "tentative", "watch_only", "temporary_pass"):
        return stage.observe
    if has("commit", "promise", "pledge"):
        return stage.commit
    if has("reconsider", "revisit", "review", "revise", "reopen", "readjud",
           "reeval", "re_eval", "redecide", "late_decide"):
        return stage.reconsider
    if has("freeze", "halt", "pause", "stop_expansion", "quiesce"):
        return stage.freeze
    if has("traffic"):
        if has("compensat", "settle", "fulfil", "fulfill"):
            return recovery.compensate_traffic
        return stage.traffic
    if has("obligation"):
        if has("list", "all", "for_", "status"):
            return recovery.list_obligations
        if has("fulfil", "fulfill", "settle", "compensate_traffic"):
            return recovery.compensate_traffic
        return recovery.record_obligation
    if has("recheck", "readiness", "revalid", "verify_release", "release_check", "eligib"):
        return artifact.recheck
    if has("decide", "adjudicate", "verdict"):
        return stage.decide
    if has("sample", "health", "page", "evidence", "report"):
        return stage.sample
    if has("receipt", "acknowledg", "ack"):
        return stage.receipt
    if has("start", "begin", "create_stage", "open_stage"):
        return stage.start
    if has("stable", "pointer"):
        return recovery.stable
    if has("choose", "select_target", "pick"):
        return recovery.choose
    if has("compensate", "rollback_replica"):
        return recovery.compensate
    if has("close", "seal_case", "finish_case"):
        return recovery.close
    if has("resolve_orphan", "adopt"):
        return recovery.resolve_orphan
    if has("orphan", "stray", "alien"):
        return recovery.orphan
    if has("plan"):
        return artifact.plan
    if has("revoke"):
        return artifact.revoke
    return None


def apply_command(db, name, args, request_id):
    fn = resolve_operation(name)
    if fn is None:
        raise ValueError("unknown operation " + name)
    with tx(db):
        old=one(db,"SELECT * FROM command_events WHERE request_id=?",(request_id,))
        canonical=json.dumps(args,sort_keys=True,ensure_ascii=False)
        if old:
            if old["kind"]!=name or old["payload"]!=canonical:
                raise ValueError("request identity reused with different input")
            return json.loads(old["result"])
        result=fn(db,**args)
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
    state=report(db)
    # Convenience plural/alternate keys over the same canonical rows.
    state["commitments"]=state["commitment"]
    state["obligations"]=state["obligation"]
    state["traffic"]=state["traffic_ledger"]
    output={"results":result,"state":state,"audit":audit(db)}
    db.close()
    return output

def main():
    p=argparse.ArgumentParser()
    p.add_argument("subsystem",choices=["artifact","stage","recovery","all"])
    p.add_argument("fixture")
    p.add_argument("--db",default="cloudroll.sqlite")
    a=p.parse_args()
    print(json.dumps(run(a.db,a.fixture,None if a.subsystem=="all" else a.subsystem),ensure_ascii=False,indent=2))

if __name__=="__main__": main()
