"""NAT 来源识别与边缘止损的独立验收测试。

覆盖：纸页重扫去重、端口复用与钟差、相容来源历史、实名通知暂缓与幂等、
两种获批处置的真实影响、旧会话未清空、交换机/容器回执、断电重启与外部
幂等回执恢复、重复通知，以及新 fixture 的命令事件审计重放。
"""
import json
import pathlib
import sqlite3
import tempfile
import unittest

from cloudroll import edge_quarantine as eq
from cloudroll import flow_capture as fc
from cloudroll import tenant_notice as tn
from cloudroll.fabric import ExternalFabric
from cloudroll.stop_loss import seed_fixed
from cloudroll.store import open_db, one, rows

ROOT = pathlib.Path(__file__).resolve().parents[1]


def fixed_rows():
    return (
        [{"edge": "e1", "ip": "10.10.0.11", "tenant": "t1", "bytes": 800,
          "egress_port": 44321, "observed_at": "10:00", "collector": "edge-A",
          "direction": "egress"}],
        [{"edge": "e1", "ip": "10.10.0.11", "tenant": "t2", "bytes": 800,
          "egress_port": 44321, "observed_at": "10:01", "collector": "edge-B",
          "direction": "egress"}],
    )


class FixedEvidence(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        r1, r2 = fixed_rows()
        self.assertEqual(fc.import_page(self.db, "p1000", r1), "captured")
        self.assertEqual(fc.import_page(self.db, "p1001", r2), "captured")
        fc.record_counter(self.db, "ctr1", edge="e1", egress_port=44321, bytes=800)
        fc.record_nat(self.db, "n1", edge="e1", egress_port=44321,
                      container="p1", tenant="t1", valid_from=570, valid_to=600)
        fc.record_nat(self.db, "n2", edge="e1", egress_port=44321,
                      container="p2", tenant="t2", valid_from=600, valid_to=660)

    def test_rescan_and_conflict_keep_single_original(self):
        r1, _ = fixed_rows()
        self.assertEqual(fc.import_page(self.db, "p1000", r1), "replayed")
        # 新页号重扫同一内容：不新增物理流
        self.assertEqual(fc.import_page(self.db, "p1000-rescan", r1), "captured")
        flows = fc.canonical_flows(self.db, edge="e1", egress_port=44321)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["confirmed_bytes"], 800)
        with self.assertRaises(ValueError):
            fc.import_page(self.db, "p1000", [{**r1[0], "bytes": 900}])

    def test_port_reuse_and_clock_skew_leave_two_histories(self):
        sources = fc.candidate_sources(self.db, edge="e1", egress_port=44321)
        self.assertEqual({(s["tenant"], s["container"]) for s in sources},
                         {("t1", "p1"), ("t2", "p2")})
        responsibility = fc.tenant_responsibility(self.db, edge="e1", egress_port=44321)
        self.assertEqual(responsibility["tenants"], [])
        self.assertTrue(responsibility["ambiguous"])
        # 两页 800 不得被当成两条流累加成 1600
        flows = fc.canonical_flows(self.db, edge="e1", egress_port=44321)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["confirmed_bytes"], 800)

    def test_earliest_label_must_not_name_t1(self):
        # 即使 10:00 最早一页写着 t1，裸 issue 也必须暂缓且不写通知账
        result = tn.issue(self.db, "t1")
        self.assertEqual(str(result), "withheld")
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM tenant_notices WHERE tenant='t1'").fetchone()[0], 0)

    def test_clock_sync_and_verified_session_narrow_to_p1(self):
        fc.record_clock(self.db, "edge-A", offset=2)
        fc.record_clock(self.db, "edge-B", offset=0)
        fc.record_session(self.db, "s1", edge="e1", egress_port=44321,
                          container="p1", tenant="t1", lease_id="n1",
                          state="established", pinning=True)
        sources = fc.candidate_sources(self.db, edge="e1", egress_port=44321)
        self.assertEqual([s["container"] for s in sources], ["p1"])
        self.assertEqual(fc.tenant_responsibility(
            self.db, edge="e1", egress_port=44321)["tenants"], ["t1"])

    def test_switch_old_session_alone_does_not_pin_tenant(self):
        fc.record_session(self.db, "old", edge="e1", egress_port=44321,
                          container="p2", tenant="t2", state="old")
        sources = fc.candidate_sources(self.db, edge="e1", egress_port=44321)
        self.assertEqual(len(sources), 2)

    def test_ingress_pages_are_not_egress_exfil(self):
        db = sqlite3.connect(":memory:")
        fc.import_page(db, "in1", [{"edge": "e9", "ip": "10.0.0.9", "tenant": "t9",
                                    "bytes": 500, "direction": "ingress",
                                    "egress_port": 44321}])
        detail = fc.locate_flow(db, edge="e9", egress_port=44321)
        self.assertEqual(detail["direction"], "ingress")


class NoticeIdempotency(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name) / "incident.sqlite"
        self.db = open_db(str(self.path))
        seed_fixed(self.db)
        # 补入收敛证据，使 t1 成为唯一责任租户
        fc.record_clock(self.db, "edge-A", offset=2)
        fc.record_clock(self.db, "edge-B", offset=0)
        fc.record_session(self.db, "s1", edge="e1", egress_port=44321,
                          container="p1", tenant="t1", pinning=True)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_duplicate_send_writes_one_notice(self):
        first = tn.send_notice(self.db, "n1", "t1", "INC-44321")
        self.assertEqual(str(first), "sent")
        replay = tn.send_notice(self.db, "n1", "t1", "INC-44321")
        self.assertTrue(replay == "duplicate" or replay == "sent")
        self.assertEqual(one(self.db,
                            "SELECT COUNT(*) n FROM verified_notice WHERE notice_id='n1'")["n"], 1)
        self.assertEqual(one(self.db,
                            "SELECT COUNT(*) n FROM tenant_notices WHERE tenant='t1'")["n"], 1)

    def test_gateway_timeout_recovers_from_external_receipt_once(self):
        fabric = ExternalFabric(notice_timeout_times=1)
        result = tn.send_notice(self.db, notice_id="n9", tenant="t1",
                                target="INC-44321", gateway=fabric)
        self.assertEqual(str(result), "send_timeout")
        self.assertEqual(one(self.db,
                            "SELECT status FROM verified_notice WHERE notice_id='n9'")["status"],
                         "send_unknown")
        # 客户端超时但外部网关确实已发，台账里有且仅有一张回执
        self.assertEqual(len(fabric.notices), 1)
        # 用同一幂等号重试：外部网关返回同一回执，不产生第二封
        retry = tn.send_notice(self.db, notice_id="n9", tenant="t1",
                               target="INC-44321", gateway=fabric)
        self.assertEqual(str(retry), "sent")
        self.assertEqual(len(fabric.notices), 1)
        # 对账同样幂等
        tn.reconcile_notices(self.db, fabric)
        tn.reconcile_notices(self.db, fabric)
        self.assertEqual(one(self.db,
                            "SELECT status FROM verified_notice WHERE notice_id='n9'")["status"],
                         "sent")
        self.assertEqual(one(self.db,
                            "SELECT COUNT(*) n FROM tenant_notices WHERE tenant='t1'")["n"], 1)

    def test_withheld_notice_survives_retry(self):
        # 未收敛的新库上 t2 也不能发
        db = sqlite3.connect(":memory:")
        seed_fixed(db)
        result = tn.send_notice(db, "nx", "t2", "INC-44321")
        self.assertEqual(str(result), "withheld")
        self.assertEqual(db.execute(
            "SELECT COUNT(*) FROM tenant_notices WHERE tenant='t2'").fetchone()[0], 0)


class EdgePlay(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        seed_fixed(self.db)

    def test_rule_without_session_clear_is_not_contained(self):
        eq.approve(self.db, order_id="o1", incident_id="INC-44321",
                   play="seal_edge", edge="e1")
        eq.install_rule(self.db, request_id="rule1", order_id="o1", edge="e1")
        eq.clear_sessions(self.db, request_id="clear1", order_id="o1", edge="e1")
        # 只有账上请求，没有任何交换机回执
        self.assertFalse(eq.is_contained(self.db, "o1"))
        eq.ingest_receipt(self.db, {"receipt_id": "r1", "request_id": "rule1",
                                    "system": "switch", "kind": "rule_effective",
                                    "status": "effective", "edge": "e1"})
        status = eq.edge_status(self.db, "o1")
        self.assertEqual(str(status["status"]), "rule_effective_sessions_pending")
        self.assertFalse(status["complete"])
        self.assertFalse(eq.verify_cut(self.db, "INC-44321")["all_cut"])
        # 旧会话仍然活着
        self.assertEqual(one(self.db,
                             "SELECT cleared FROM net_session WHERE session_id='old-conntrack-44321'")
                         ["cleared"], 0)
        # 清空回执到达后才完成
        eq.ingest_receipt(self.db, {"receipt_id": "r2", "request_id": "clear1",
                                    "system": "switch", "kind": "sessions_cleared",
                                    "status": "confirmed", "edge": "e1"})
        status = eq.edge_status(self.db, "o1")
        self.assertTrue(status["complete"])
        self.assertTrue(eq.verify_cut(self.db, "INC-44321")["all_cut"])
        self.assertEqual(one(self.db,
                             "SELECT cleared FROM net_session WHERE session_id='old-conntrack-44321'")
                         ["cleared"], 1)

    def test_edge_play_impact_is_whole_e1_t1_t2_brief_outage(self):
        fabric = ExternalFabric()
        code = eq.seal_edge(self.db, edge="e1", order_id="oe",
                            incident_id="INC-44321", request_id="req-e", fabric=fabric)
        self.assertEqual(str(code), "contained")
        order = one(self.db, "SELECT * FROM response_order WHERE order_id='oe'")
        impact = json.loads(order["approved_impact"])
        self.assertEqual(impact["edge"], "e1")
        self.assertTrue(impact["all_customers_on_edge"])
        self.assertEqual(set(impact["tenants"]), {"t1", "t2"})
        kinds = {r["kind"] for r in fabric.ledger()}
        self.assertIn("rule_effective", kinds)
        self.assertIn("sessions_cleared", kinds)
        self.assertTrue(eq.verify_cut(self.db)["all_cut"])

    def test_approval_scope_violation_rejected(self):
        # 只批准 t1 的影响范围，却要封整个 e1（会波及 t2）：必须拒绝
        eq.approve(self.db, order_id="tight", play="seal_edge", edge="e1",
                   approved_impact={"kind": "edge", "edge": "e1", "tenants": ["t1"]})
        code = eq.seal_edge(self.db, order_id="tight", edge="e1")
        self.assertEqual(str(code), "impact_outside_approval")
        self.assertIsNone(one(self.db, "SELECT 1 x FROM switch_rule WHERE order_id='tight'"))


class ContainerPlay(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        seed_fixed(self.db)

    def test_unrelated_traffic_must_move_before_forensics(self):
        eq.migrate_traffic(self.db, request_id="m1", container="p1",
                           workloads=["svc-x"])
        code = eq.isolate_containers(self.db, containers=["p1", "p2"],
                                     order_id="oc")
        self.assertEqual(str(code), "traffic_not_migrated")
        # 迁移回执确认后才允许
        eq.ingest_receipt(self.db, {"request_id": "m1", "system": "container",
                                    "kind": "traffic_migrated", "status": "confirmed",
                                    "container": "p1"})
        code = eq.isolate_containers(self.db, containers=["p1", "p2"], order_id="oc")
        self.assertEqual(str(code), "partial")  # 动作已请求，回执未齐

    def test_both_candidates_cut_and_other_e1_customers_unaffected(self):
        fabric = ExternalFabric()
        eq.migrate_traffic(self.db, request_id="m1", container="p1",
                           workloads=["svc-x"])
        fabric.migrate_traffic("m1", "p1", ["svc-x"])
        eq.ingest_receipt(self.db, fabric.receipts_for("m1")[0])
        code = eq.isolate_containers(self.db, containers=["p1", "p2"],
                                     order_id="oc", fabric=fabric)
        self.assertEqual(str(code), "contained")
        status = eq.container_status(self.db, "oc")
        self.assertTrue(status["complete"])
        self.assertEqual({t["container"] for t in status["targets"]}, {"p1", "p2"})
        self.assertTrue(eq.verify_cut(self.db, "INC-44321")["all_cut"])
        # 影响范围严格等于两个候选容器，e1 其他客户不在隔离集合
        order = one(self.db, "SELECT targets FROM response_order WHERE order_id='oc'")
        self.assertEqual(set(json.loads(order["targets"])), {"p1", "p2"})

    def test_missing_one_container_receipt_is_not_complete(self):
        eq.isolate_containers(self.db, containers=["p1", "p2"], order_id="oc2")
        # 只给 p1 两张回执：通过请求号定位
        actions = rows(self.db,
                        "SELECT request_id,kind FROM container_action WHERE container='p1'")
        for a in actions:
            kind = ("move_forensics" if a["kind"] == "move_forensics"
                    else "revoke_egress")
            eq.container_receipt(self.db, {"receipt_id": "r-" + a["request_id"],
                                           "request_id": a["request_id"],
                                           "system": "container", "kind": kind,
                                           "status": "confirmed", "container": "p1"})
        self.assertFalse(eq.container_status(self.db, "oc2")["complete"])
        self.assertFalse(eq.verify_cut(self.db)["all_cut"])


class PowerLossRecovery(unittest.TestCase):
    def test_reopen_and_reconcile_external_receipts(self):
        temp = tempfile.TemporaryDirectory()
        path = pathlib.Path(temp.name) / "power.sqlite"
        db = open_db(str(path))
        seed_fixed(db)
        fabric = ExternalFabric()
        eq.seal_edge(db, edge="e1", order_id="o1", request_id="req", fabric=fabric)
        # 已保存回执时，断电重开仍是 contained
        db.close()
        db = open_db(str(path))
        self.assertTrue(eq.is_contained(db, "o1"))
        self.assertTrue(eq.verify_cut(db)["all_cut"])
        # 原页仍在，且没有重复页
        self.assertEqual(one(db, "SELECT COUNT(*) n FROM flow_pages")["n"], 2)
        db.close()
        temp.cleanup()

    def test_rule_live_but_db_lost_reconstruct_from_ledger(self):
        temp = tempfile.TemporaryDirectory()
        path = pathlib.Path(temp.name) / "lost.sqlite"
        # 现场交换机已生效，只有外部台账 survives
        fabric = ExternalFabric()
        fabric.install_edge_rule("rule-X", "e1")
        fabric.clear_edge_sessions("clear-X", "e1", count=1)
        # 全新本地库（断电丢失未入库状态），重装原页后凭台账恢复实际历史
        db = open_db(str(path))
        r1, r2 = fixed_rows()
        fc.import_page(db, "p1000", r1)
        fc.import_page(db, "p1001", r2)
        result = eq.reconcile(db, fabric.ledger())
        self.assertGreaterEqual(result["applied"], 2)
        status = eq.edge_status(db, edge="e1")
        self.assertTrue(status["rule_effective"])
        self.assertTrue(status["sessions_cleared"])
        # 重复对账幂等
        again = eq.reconcile(db, fabric)
        self.assertEqual(again["applied"], 0)
        db.close()
        temp.cleanup()

    def test_container_ledger_reconstructs_on_fresh_db(self):
        fabric = ExternalFabric()
        fabric.move_to_forensics("move-p1", "p1")
        fabric.revoke_egress("revoke-p1", "p1")
        fabric.move_to_forensics("move-p2", "p2")
        fabric.revoke_egress("revoke-p2", "p2")
        temp = tempfile.TemporaryDirectory()
        db = open_db(str(pathlib.Path(temp.name) / "c.sqlite"))
        eq.reconcile(db, fabric.ledger())
        status = eq.container_status(db, ["p1", "p2"])
        self.assertTrue(status["complete"])
        db.close()
        temp.cleanup()

    def test_raw_sqlite_file_power_loss_commits(self):
        temp = tempfile.TemporaryDirectory()
        path = str(pathlib.Path(temp.name) / "raw.db")
        db = sqlite3.connect(path)  # 裸连接，非 store.open_db
        seed_fixed(db)
        eq.seal_edge(db, edge="e1", order_id="o1", request_id="req",
                     fabric=ExternalFabric())
        db.close()
        db = sqlite3.connect(path)
        self.assertTrue(eq.is_contained(db, "o1"))
        self.assertEqual(db.execute("SELECT COUNT(*) FROM flow_pages").fetchone()[0], 2)
        db.close()
        temp.cleanup()

    def test_corrections_append_without_overwriting_pages(self):
        db = sqlite3.connect(":memory:")
        r1, _ = fixed_rows()
        fc.import_page(db, "p1000", r1)
        fc.append_correction(db, "corr1", incident_id="INC",
                             target_kind="tenant_label", target_id="p1000:1",
                             field="tenant", old_value="t1", new_value="unverified",
                             reason="collector clock skew")
        fc.append_correction(db, "corr1", reason="idempotent replay")
        self.assertEqual(db.execute(
            "SELECT COUNT(*) FROM evidence_correction WHERE correction_id='corr1'").fetchone()[0], 1)
        # 原页标签保持不变
        self.assertEqual(db.execute(
            "SELECT tenant FROM flow_rows WHERE page='p1000'").fetchone()[0], "t1")


class FixtureAudit(unittest.TestCase):
    def test_egress_fixture_replays_and_audits(self):
        from cloudroll.cli import run
        temp = tempfile.TemporaryDirectory()
        out = run(str(pathlib.Path(temp.name) / "f.sqlite"),
                  ROOT / "fixtures" / "stop_loss_delivery.json")
        self.assertTrue(out["audit"]["verified"], out["audit"]["mismatches"])
        self.assertEqual(out["results"][-1]["result"]["complete"], True)
        temp.cleanup()

    def test_alias_surface_importable(self):
        import cloudroll.nat_trace as nt
        import cloudroll.incident as inc
        for mod in (nt, inc):
            self.assertTrue(callable(mod.identify_sources))
            self.assertTrue(callable(mod.seal_edge))
            self.assertTrue(callable(mod.send_notice))
            self.assertTrue(callable(mod.reconcile))


if __name__ == "__main__":
    unittest.main()
