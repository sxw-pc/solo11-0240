"""固定原件场景与“真正可执行”的止损指令。

固定证据：e1 出口 44321 端口，10:00 页记 t1 外传 800，10:01 页记 t2 外传 800；
钟差与端口复用使两种来源历史（t1/p1 与 t2/p2）尚相容，独立计数器确认出口总量 800。

本模块可直接执行两种获批做法，保存交换机/容器幂等回执：

    python -m cloudroll.stop_loss edge --db stop.sqlite --receipts stop.json
    python -m cloudroll.stop_loss containers
"""
from __future__ import annotations

import argparse
import json

from . import edge_quarantine as eq
from . import flow_capture as fc
from . import stage
from . import tenant_notice as tn
from .fabric import ExternalFabric
from .store import open_db

FIXED_PAGES = [
    {"page": "egress-1000", "collector": "edge-A", "observed_at": "10:00",
     "rows": [{"edge": "e1", "ip": "10.10.0.11", "tenant": "t1", "bytes": 800,
               "egress_port": 44321, "protocol": "tcp", "direction": "egress",
               "src_ip": "172.17.0.11", "src_port": 51000,
               "dst_ip": "203.0.113.9", "dst_port": 8443}]},
    {"page": "egress-1001", "collector": "edge-B", "observed_at": "10:01",
     "rows": [{"edge": "e1", "ip": "10.10.0.11", "tenant": "t2", "bytes": 800,
               "egress_port": 44321, "protocol": "tcp", "direction": "egress",
               "src_ip": "172.17.0.22", "src_port": 51001,
               "dst_ip": "203.0.113.9", "dst_port": 8443}]},
]


def seed_fixed(db, counter_bytes=800, old_sessions=True):
    """装入固定原件：两页、独立计数器、两条相容 NAT 租期、一条交换机旧会话。"""
    for page in FIXED_PAGES:
        fc.import_page(db, page["page"], page["rows"])
    fc.record_counter(db, "ctr-e1-44321", edge="e1", egress_port=44321,
                      bytes=counter_bytes, window_start="10:00", window_end="10:02",
                      collector="independent-meter")
    fc.record_nat(db, "nat-epoch-1", edge="e1", egress_port=44321, protocol="tcp",
                  egress_ip="198.51.100.1", internal_ip="172.17.0.11",
                  container="p1", tenant="t1", epoch=1,
                  valid_from="09:30", valid_to="10:00", status="expired-reused")
    fc.record_nat(db, "nat-epoch-2", edge="e1", egress_port=44321, protocol="tcp",
                  egress_ip="198.51.100.1", internal_ip="172.17.0.22",
                  container="p2", tenant="t2", epoch=2,
                  valid_from="10:00", valid_to="11:00", status="active")
    if old_sessions:
        # 交换机旧连接表里的陈旧条目：仍是必须清空的活路径（只加规则切不断它），
        # 但在校时/五元组会话证据补齐前不能单凭它把来源钉给 p2。
        fc.record_session(db, "old-conntrack-44321", edge="e1", egress_port=44321,
                          protocol="tcp", container="p2", tenant="t2",
                          lease_id="nat-epoch-2", state="old",
                          bytes=800, last_seen_at="10:01", direction="egress")
    fc.identify_sources(db, "INC-44321")
    return db


def evidence_summary(db):
    sources = fc.candidate_sources(db, "INC-44321")
    responsibility = fc.tenant_responsibility(db, "INC-44321")
    flows = fc.canonical_flows(db, "INC-44321")
    return {
        "candidate_sources": sources,
        "candidate_tenants": responsibility["candidate_tenants"],
        "notifiable_tenants": responsibility["tenants"],
        "ambiguous": responsibility["ambiguous"],
        "flows": [{k: v for k, v in f.items() if k != "pages"} for f in flows],
        "real_name_notice": "withheld_pending_source_convergence",
    }


def execute_edge_play(db, fabric=None):
    """做法一：封 e1 全出口 + 清空旧会话。t1/t2 短暂断网，无需先判明容器。"""
    fabric = fabric or ExternalFabric()
    stage.open_incident(db, "INC-EDGE", edge="e1", egress_port=44321,
                        play="seal_edge", approved_by="security-officer",
                        ops_lead="ops-lead",
                        impact={"kind": "edge", "edge": "e1",
                                "all_customers_on_edge": True,
                                "tenants": ["t1", "t2"]})
    execution = stage.execute_response(db, "INC-EDGE", fabric=fabric)
    # 实名通知在责任收敛前一律暂缓（幂等记录 held，不写 tenant_notices）。
    held = tn.send_notice(db, notice_id="notice-INC-44321-t1", tenant="t1",
                          target="INC-44321")
    return {
        "play": "seal_entire_e1_and_clear_sessions",
        "approved_impact": {"brief_outage_tenants": ["t1", "t2"],
                            "other_e1_customers": "brief_outage_as_whole_edge"},
        "execution": _jsonable(execution),
        "notice_decision": str(held),
        "switch_receipts": fabric.ledger(),
    }


def execute_container_play(db, fabric=None):
    """做法二：p1/p2 先迁无关流量，再入取证网并撤外传；e1 其他客户不受影响。"""
    fabric = fabric or ExternalFabric()
    # 示范 p1 上有一项无关服务需要先迁走并取得迁移回执。
    eq.migrate_traffic(db, request_id="mig-p1-svc", container="p1",
                       workloads=["unrelated-svc"], tenant="other-customer")
    fabric.migrate_traffic("mig-p1-svc", "p1", ["unrelated-svc"])
    eq.ingest_receipt(db, fabric.receipts_for("mig-p1-svc")[0])
    stage.open_incident(db, "INC-CONTAINERS", edge="e1", egress_port=44321,
                        play="isolate_containers", candidates=["p1", "p2"],
                        approved_by="security-officer", ops_lead="ops-lead",
                        impact={"kind": "containers", "containers": ["p1", "p2"]})
    execution = stage.execute_response(db, "INC-CONTAINERS", fabric=fabric)
    return {
        "play": "forensic_isolation_of_p1_p2_after_traffic_migration",
        "approved_impact": {"isolated_containers": ["p1", "p2"],
                            "e1_other_customers": "continue_serving"},
        "execution": _jsonable(execution),
        "container_receipts": [r for r in fabric.ledger()
                               if r.get("system") == "container"],
    }


def execute_fixed(play="edge", db_path=None, receipts_path=None):
    """在文件库（断电可重开）或内存库上执行固定场景，返回可 JSON 序列化交付包。"""
    db = open_db(db_path) if db_path else __import__("sqlite3").connect(":memory:")
    if db_path is None:
        db.row_factory = __import__("sqlite3").Row
    seed_fixed(db)
    bundle = {"evidence": evidence_summary(db)}
    if play in ("edge", "both"):
        bundle["edge_play"] = execute_edge_play(db)
    if play in ("containers", "both"):
        bundle["container_play"] = execute_container_play(db)
    bundle["recovery_runbook"] = [
        "保持 e1 拒绝规则生效，并确认交换机会话表清空回执；",
        "断电重启后用 reconcile 从交换机/容器/通知网关的幂等回执重建实际历史；",
        "补入校时偏移与真实会话证据后重跑 identify_sources 缩小责任；",
        "仅当某租户在全部相容历史中成立时才 send_notice 发实名通知；",
        "恢复：先回迁取证容器/撤销临时规则，核对会话重建与字节计数器后关单。",
    ]
    bundle["event_sourced_audit"] = (
        "python -m cloudroll all fixtures/egress_incident.json --db incident.sqlite "
        "输出中的 audit.verified 才代表状态可由命令事件重放重建")
    if receipts_path:
        with open(receipts_path, "w", encoding="utf-8") as handle:
            json.dump(bundle, handle, ensure_ascii=False, indent=2, default=str)
    if db_path:
        db.close()
    return bundle


def _jsonable(value):
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def main(argv=None):
    parser = argparse.ArgumentParser(description="执行 e1:44321 获批止损做法")
    parser.add_argument("play", choices=["edge", "containers", "both"], nargs="?",
                        default="edge")
    parser.add_argument("--db", default="stop_loss.sqlite")
    parser.add_argument("--receipts", default="stop_loss_receipts.json")
    args = parser.parse_args(argv)
    bundle = execute_fixed(args.play, args.db, args.receipts)
    print(json.dumps({"receipts": args.receipts,
                      "evidence": bundle["evidence"],
                      "audit": bundle.get("audit")}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
