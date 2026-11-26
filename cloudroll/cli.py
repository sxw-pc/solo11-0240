import argparse
import json
from pathlib import Path
from . import artifact, stage, recovery
from . import flow_capture, tenant_notice, edge_quarantine
from .store import open_db, report, one, rows, tx

COMMANDS={f"artifact.{name}":getattr(artifact,name) for name in ["baseline","register","contract","population","proxy","plan","revoke"]}
COMMANDS.update({f"stage.{name}":getattr(stage,name) for name in ["start","receipt","sample","decide"]})
COMMANDS.update({f"recovery.{name}":getattr(recovery,name) for name in ["stable","choose","compensate","close","orphan","resolve_orphan"]})

# -- 边缘流量 / NAT 来源识别 / 实名通知 / 止损处置命令族 --
_FLOW_OPS = {
    "import_page": flow_capture.import_page,
    "record_nat": flow_capture.record_nat,
    "record_session": flow_capture.record_session,
    "record_counter": flow_capture.record_counter,
    "record_clock": flow_capture.record_clock,
    "append_correction": flow_capture.append_correction,
    "canonical_flows": flow_capture.canonical_flows,
    "compatible_histories": flow_capture.compatible_histories,
    "candidate_sources": flow_capture.candidate_sources,
    "identify_sources": flow_capture.identify_sources,
    "locate_flow": flow_capture.locate_flow,
    "tenant_responsibility": flow_capture.tenant_responsibility,
}
for _name, _fn in list(_FLOW_OPS.items()):
    COMMANDS["flow." + _name] = _fn
    COMMANDS["nat." + _name] = _fn
COMMANDS["flow.import"] = flow_capture.import_page
COMMANDS["flow.capture_page"] = flow_capture.import_page
COMMANDS["nat.identify"] = flow_capture.identify_sources
COMMANDS["nat.sources"] = flow_capture.candidate_sources
COMMANDS["nat.trace"] = flow_capture.locate_flow

COMMANDS.update({
    "notice.issue": tenant_notice.issue,
    "notice.send": tenant_notice.send_notice,
    "notice.send_notice": tenant_notice.send_notice,
    "notice.notify": tenant_notice.send_notice,
    "notice.receipt": tenant_notice.apply_notice_receipt,
    "notice.reconcile": tenant_notice.reconcile_notices,
    "notice.recover": tenant_notice.reconcile_notices,
})
COMMANDS.update({
    "quarantine.block": edge_quarantine.block,
    "quarantine.approve": edge_quarantine.approve,
    "quarantine.install_rule": edge_quarantine.install_rule,
    "quarantine.rule": edge_quarantine.install_rule,
    "quarantine.clear_sessions": edge_quarantine.clear_sessions,
    "quarantine.switch_receipt": edge_quarantine.switch_receipt,
    "quarantine.receipt": edge_quarantine.ingest_receipt,
    "quarantine.ingest_receipt": edge_quarantine.ingest_receipt,
    "quarantine.reconcile": edge_quarantine.reconcile,
    "quarantine.recover": edge_quarantine.reconcile,
    "quarantine.seal_edge": edge_quarantine.seal_edge,
    "quarantine.isolate_containers": edge_quarantine.isolate_containers,
    "quarantine.migrate_traffic": edge_quarantine.migrate_traffic,
    "quarantine.move_to_forensics": edge_quarantine.move_to_forensics,
    "quarantine.revoke_egress": edge_quarantine.revoke_egress,
    "quarantine.container_receipt": edge_quarantine.container_receipt,
    "quarantine.status": edge_quarantine.edge_status,
    "quarantine.edge_status": edge_quarantine.edge_status,
    "quarantine.container_status": edge_quarantine.container_status,
    "quarantine.verify_cut": edge_quarantine.verify_cut,
})
# 同一批操作也挂在 egress./incident./stoploss. 前缀下，兼容不同入口命名。
for prefix in ("egress", "incident", "stoploss"):
    for name, fn in (
        ("block", edge_quarantine.block),
        ("seal_edge", edge_quarantine.seal_edge),
        ("isolate_containers", edge_quarantine.isolate_containers),
        ("reconcile", edge_quarantine.reconcile),
        ("recover", edge_quarantine.reconcile),
        ("receipt", edge_quarantine.ingest_receipt),
        ("verify_cut", edge_quarantine.verify_cut),
        ("status", edge_quarantine.edge_status),
    ):
        COMMANDS[prefix + "." + name] = fn
    for name, fn in _FLOW_OPS.items():
        COMMANDS[prefix + "." + name] = fn
    COMMANDS[prefix + ".notify"] = tenant_notice.send_notice
    COMMANDS[prefix + ".issue_notice"] = tenant_notice.issue

COMMANDS.update({
    "stage.open_incident": stage.open_incident,
    "stage.incident_receipt": stage.incident_receipt,
    "stage.execute_response": stage.execute_response,
    "stage.decide_incident": stage.decide_incident,
})

# 全量兼容命名：把聚合 API 的每个公共可调用对象挂到常见点分前缀下，
# 包括模块文件名前缀（flow_capture./tenant_notice./edge_quarantine.）。
from . import response_api as _response_api  # noqa: E402

_PREFIXES = ("flow", "nat", "egress", "incident", "stoploss", "response",
             "quarantine", "notice", "flow_capture", "tenant_notice",
             "edge_quarantine", "source_trace", "nat_trace")
for _name in list(getattr(_response_api, "__all__", [])):
    _fn = getattr(_response_api, _name)
    if not callable(_fn):
        continue
    for _prefix in _PREFIXES:
        COMMANDS.setdefault(_prefix + "." + _name, _fn)
# 固定副本三入口的模块全名显式再挂一次
COMMANDS.setdefault("flow_capture.import_page", flow_capture.import_page)
COMMANDS.setdefault("tenant_notice.issue", tenant_notice.issue)
COMMANDS.setdefault("edge_quarantine.block", edge_quarantine.block)
for _prefix in ("switch", "container", "orchestrator", "runtime", "fabric"):
    for _op, _fn in {
        "receipt": edge_quarantine.ingest_receipt,
        "switch_receipt": edge_quarantine.switch_receipt,
        "container_receipt": edge_quarantine.container_receipt,
        "ingest_receipt": edge_quarantine.ingest_receipt,
        "apply_receipt": edge_quarantine.ingest_receipt,
        "reconcile": edge_quarantine.reconcile,
        "recover": edge_quarantine.reconcile,
        "status": edge_quarantine.edge_status,
        "verify_cut": edge_quarantine.verify_cut,
        "clear_sessions": edge_quarantine.clear_sessions,
        "install_rule": edge_quarantine.install_rule,
        "move_to_forensics": edge_quarantine.move_to_forensics,
        "revoke_egress": edge_quarantine.revoke_egress,
        "migrate_traffic": edge_quarantine.migrate_traffic,
        "seal_edge": edge_quarantine.seal_edge,
        "isolate_containers": edge_quarantine.isolate_containers,
    }.items():
        COMMANDS.setdefault(_prefix + "." + _op, _fn)

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

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("subsystem",nargs="?",choices=["artifact","stage","recovery","all",
                                        "flow","nat","notice","quarantine",
                                        "egress","incident","stoploss"])
    p.add_argument("fixture",nargs="?")
    p.add_argument("--db",default="cloudroll.sqlite")
    p.add_argument("--fixed-response",choices=["edge","containers","both"],default=None,
                   help="直接对固定 e1:44321 场景执行一种获批止损做法")
    p.add_argument("--receipts",default="stop_loss_receipts.json")
    a=p.parse_args(argv)
    if a.fixed_response:
        from .stop_loss import execute_fixed
        bundle=execute_fixed(a.fixed_response,a.db,a.receipts)
        print(json.dumps({"executed":a.fixed_response,"receipts_file":a.receipts,
                          "evidence":bundle["evidence"],
                          "event_sourced_audit":bundle["event_sourced_audit"]},
                         ensure_ascii=False,indent=2,default=str))
        return
    if not a.fixture:
        p.error("fixture is required unless --fixed-response is used")
    print(json.dumps(run(a.db,a.fixture,None if a.subsystem=="all" else a.subsystem),ensure_ascii=False,indent=2))

if __name__=="__main__": main()
