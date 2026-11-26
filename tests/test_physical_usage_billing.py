import pathlib
import tempfile
import unittest

from cloudroll import artifact, stage
from cloudroll.cli import apply_command, audit, run
from cloudroll.meter_capture import import_page
from cloudroll.physical_usage import (alias, calibrate, container, deploy_proof,
                                      dispatch, migrate, reconcile)
from cloudroll.store import one, open_db, rows
from cloudroll.tenant_charge import issue
from cloudroll.vendor_payable import close

PAGE = [
    {"host": "hostA", "tenant": "t1", "minute": 10, "core_seconds": 60},
    {"host": "hostB", "tenant": "t2", "minute": 10, "core_seconds": 30},
]


class PhysicalUsageBilling(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.temp.name) / "billing.sqlite"))

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def charges(self, tenant):
        return rows(self.db, "SELECT tenant,core_seconds,kind,batch,signer "
                             "FROM tenant_charges WHERE tenant=? ORDER BY id", (tenant,))

    def seed_main_example(self):
        # 两家供应商门户各自夜交纸页；甲宿主一行被两个门户复抄。
        self.assertEqual(import_page(self.db, "v1:p1", PAGE), "captured")
        self.assertEqual(import_page(self.db, "v2:p1", [PAGE[0]]), "captured")
        # 控制器共同校时证明总量仍是 90。
        self.assertEqual(calibrate(self.db, "cal1", "controller", [
            {"host": "hostA", "minute": 10, "core_seconds": 60},
            {"host": "hostB", "minute": 10, "core_seconds": 30}], 90), "accepted")
        # 完整条码分属两租户，仅末四位不同。
        self.assertEqual(container(self.db, "CNTR-8842-1001", "t1"), "accepted")
        self.assertEqual(container(self.db, "CNTR-8842-1002", "t2"), "accepted")
        # 甲宿主迁移条码缺末四位；乙宿主完整条码确证 t2。
        self.assertEqual(migrate(self.db, "m1", "hostA", "CNTR-8842-10", 10, 10), "recorded")
        self.assertEqual(migrate(self.db, "m2", "hostB", "CNTR-8842-1002", 10, 10), "recorded")

    def test_duplicate_pages_pay_once_and_hold_unproven_tenant(self):
        self.seed_main_example()
        # 复抄不创造核秒：物理总量 90 而非 150，且同控制器原件守恒。
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM physical_usage")["n"], 2)
        self.assertEqual(close(self.db, "inv-1", signer="procurement"), 90)
        # 租户身份未定不免除供应商债务，但 t1 只能暂不开票，t2 开确证的 30。
        self.assertEqual(issue(self.db, "t1", signer="billing"), 0)
        self.assertEqual(issue(self.db, "t2", signer="billing"), 30)
        view = reconcile(self.db)
        self.assertEqual((view["vendor_due"], view["confirmed"], view["held"]), (90, 30, 60))
        self.assertEqual(view["confirmed"] + view["held"], view["physical"])
        self.assertEqual(self.charges("t1"), [])

    def test_complete_barcode_after_bank_batch_issues_supplementary_invoice(self):
        self.seed_main_example()
        close(self.db, "inv-1", signer="procurement")
        issue(self.db, "t2", signer="billing")
        self.assertEqual(dispatch(self.db, "vendor"), "vendor-batch-1")
        self.assertEqual(dispatch(self.db, "tenant"), "tenant-batch-1")
        # 银行批次发出后补到完整迁移条码：精化观测，旧回单不动。
        self.assertEqual(migrate(self.db, "m1", "hostA", "CNTR-8842-1001", 10, 10), "refined")
        self.assertEqual(issue(self.db, "t1", signer="billing"), 60)
        self.assertEqual(issue(self.db, "t2", signer="billing"), 0)
        t1 = self.charges("t1")
        self.assertEqual([(c["core_seconds"], c["kind"]) for c in t1],
                         [(60, "supplementary")])
        self.assertEqual(t1[0]["batch"], "tenant-batch-2")
        # 旧回单仍在且未改：t2 的 30 还是 initial。
        self.assertEqual([(c["core_seconds"], c["kind"]) for c in self.charges("t2")],
                         [(30, "initial")])
        self.assertEqual(reconcile(self.db)["tenant_posted"], 90)

    def test_wrong_charge_is_reversed_with_real_fund_correction(self):
        # 旧版只凭网页栏开票的错收场景：批次已发出，完整条码证明容器属 t2。
        self.assertEqual(import_page(self.db, "v1:p1", PAGE), "captured")
        self.assertEqual(issue(self.db, "t1", signer="billing"), 60)
        self.assertEqual(issue(self.db, "t2", signer="billing"), 30)
        self.assertEqual(dispatch(self.db, "tenant"), "tenant-batch-1")
        self.assertEqual(container(self.db, "CNTR-8842-1002", "t2"), "accepted")
        self.assertEqual(migrate(self.db, "m1", "hostA", "CNTR-8842-1002", 10, 10), "recorded")
        # 物理归属推翻网页标签：t1 冲回 60，t2 补票 60，实际资金冲正。
        self.assertEqual(issue(self.db, "t1", signer="billing"), -60)
        self.assertEqual(issue(self.db, "t2", signer="billing"), 60)
        self.assertEqual([(c["core_seconds"], c["kind"]) for c in self.charges("t1")],
                         [(60, "initial"), (-60, "reversal")])
        self.assertEqual([(c["core_seconds"], c["kind"]) for c in self.charges("t2")],
                         [(30, "initial"), (60, "supplementary")])
        # 供应商账不受归属纠错影响：仍欠 90，重复结账只回放原回单。
        self.assertEqual(close(self.db, "inv-1", signer="procurement"), 90)
        self.assertEqual(close(self.db, "inv-1", signer="procurement"), 90)
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM vendor_payables")["n"], 1)

    def test_host_alias_and_cross_vendor_duplicate_collapse_to_one_cell(self):
        self.assertEqual(import_page(self.db, "v1:p1", [
            {"host": "hostA", "tenant": "t1", "minute": 10, "core_seconds": 60}]), "captured")
        # 另一供应商门户用全限定名复抄同一物理宿主同一分钟。
        self.assertEqual(import_page(self.db, "v2:p7", [
            {"host": "hostA.example.com", "tenant": "t1", "minute": 10,
             "core_seconds": 60}]), "captured")
        # 别名晚到也生效：重算后两页折叠为一个物理单元。
        self.assertEqual(alias(self.db, "hostA.example.com", "hostA"), "accepted")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM physical_usage")["n"], 1)
        self.assertEqual(close(self.db, "inv-1"), 60)
        with self.assertRaises(ValueError):
            alias(self.db, "hostA.example.com", "other-host")

    def test_conflicting_web_labels_are_held_not_first_come_first_served(self):
        # 同一物理单元两页标签不一致：不得按上传先后择一，挂起等物理证据。
        self.assertEqual(import_page(self.db, "v1:p1", [PAGE[0]]), "captured")
        self.assertEqual(import_page(self.db, "v2:p1", [
            {"host": "hostA", "tenant": "t2", "minute": 10, "core_seconds": 60}]), "captured")
        self.assertEqual(issue(self.db, "t1"), 0)
        self.assertEqual(issue(self.db, "t2"), 0)
        self.assertEqual(reconcile(self.db)["held"], 60)
        self.assertEqual(close(self.db, "inv-1"), 60)

    def test_physical_reading_conflict_rolls_back_whole_page(self):
        self.assertEqual(import_page(self.db, "v1:p1", PAGE), "captured")
        with self.assertRaises(ValueError):
            import_page(self.db, "v2:p9", [
                {"host": "hostA", "tenant": "t1", "minute": 10, "core_seconds": 70}])
        # 失败批次不留半本账：冲突页及其行整体不存在，原账可继续结账。
        self.assertIsNone(one(self.db, "SELECT id FROM meter_pages WHERE id='v2:p9'"))
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM meter_rows")["n"], 2)
        self.assertEqual(close(self.db, "inv-1"), 90)

    def test_controller_calibration_skew_and_divergence(self):
        self.assertEqual(import_page(self.db, "v1:p1", [PAGE[0]]), "captured")
        # 共同校时偏差一分钟内可归一：控制器第 11 分钟即门户第 10 分钟。
        self.assertEqual(calibrate(self.db, "cal-skew", "controller", [
            {"host": "hostA", "minute": 11, "core_seconds": 60}], 60, skew=1), "accepted")
        self.assertEqual(close(self.db, "inv-1"), 60)
        # 偏差超阈拒绝且不留痕迹。
        self.assertEqual(calibrate(self.db, "cal-wide", "controller", [
            {"host": "hostA", "minute": 12, "core_seconds": 60}], 60, skew=2),
            "calibration_skew_exceeded")
        self.assertIsNone(one(self.db, "SELECT id FROM calibration WHERE id='cal-wide'"))
        # 校验和自证不符拒绝。
        self.assertEqual(calibrate(self.db, "cal-sum", "controller", [
            {"host": "hostA", "minute": 10, "core_seconds": 60}], 61),
            "calibration_total_mismatch")

    def test_controller_divergence_blocks_close_atomically_and_unmetered_is_paid(self):
        self.assertEqual(import_page(self.db, "v1:p1", [PAGE[0]]), "captured")
        self.assertEqual(calibrate(self.db, "cal1", "controller", [
            {"host": "hostA", "minute": 10, "core_seconds": 70}], 70), "accepted")
        # 纸页与控制器原件分歧：整批拒付，不产生任何应付回单。
        self.assertEqual(close(self.db, "inv-1"), "controller_divergence:hostA@10")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM vendor_payables")["n"], 0)
        # 控制器证明存在而纸页未到的耗用仍须建付款责任。
        self.assertEqual(calibrate(self.db, "cal2", "controller", [
            {"host": "hostB", "minute": 10, "core_seconds": 30}], 30), "accepted")
        self.assertEqual(close(self.db, "inv-2"), "controller_divergence:hostA@10")
        db2 = open_db(str(pathlib.Path(self.temp.name) / "second.sqlite"))
        try:
            import_page(db2, "p1", [PAGE[0]])
            calibrate(db2, "cal", "controller", [
                {"host": "hostA", "minute": 10, "core_seconds": 60},
                {"host": "hostB", "minute": 10, "core_seconds": 30}], 90)
            self.assertEqual(close(db2, "inv"), 90)
            self.assertEqual(reconcile(db2)["controller_attested"], 30)
        finally:
            db2.close()

    def test_migration_across_release_windows_with_deploy_proof(self):
        # 发行侧：计划窗口内一个阶段，副本 r1 回执齐全并通过。
        artifact.baseline(self.db, "svc", 3, 1)
        artifact.register(self.db, "img", "imghash", 2, 4)
        artifact.contract(self.db, "img", 1, 3)
        artifact.population(self.db, "svc", 1, 5)
        self.assertEqual(artifact.plan(self.db, "e1", "plan", "svc", "img", 1, 20), "locked")
        self.assertEqual(stage.start(self.db, "s1", "plan",
                                     [{"replica": "r1", "generation": 1}], 2, 10), "started")
        self.assertEqual(stage.receipt(self.db, "ack1", "s1", "r1", 1, "imghash"), "recorded")
        # 阶段回执证明部署副本：容器注册串起发行窗与计量归属。
        self.assertEqual(deploy_proof(self.db, "CNTR-7-0001", "t1", "s1", "r1"), "accepted")
        self.assertEqual(deploy_proof(self.db, "CNTR-7-0002", "t2", "s1", "ghost"),
                         "deployment_not_proven")
        # 跨发行窗迁移：窗口前半在 hostA，后半迁到 hostB，归属同为 t1。
        self.assertEqual(migrate(self.db, "m1", "hostA", "CNTR-7-0001", 2, 10), "recorded")
        self.assertEqual(migrate(self.db, "m2", "hostB", "CNTR-7-0001", 11, 20), "recorded")
        self.assertEqual(import_page(self.db, "v1:p1", [
            {"host": "hostA", "tenant": "t9", "minute": 5, "core_seconds": 40},
            {"host": "hostB", "tenant": "t9", "minute": 15, "core_seconds": 40}]), "captured")
        # 物理迁移证据压倒网页标签 t9。
        self.assertEqual(issue(self.db, "t1"), 80)
        self.assertEqual(issue(self.db, "t9"), 0)
        self.assertEqual(close(self.db, "inv-1"), 80)

    def test_independent_signers_for_procurement_and_customer_billing(self):
        self.assertEqual(import_page(self.db, "v1:p1", PAGE), "captured")
        self.assertEqual(close(self.db, "inv-1", signer="alice"), 90)
        # 同一具名签发人不得跨采购与客户账务两本账。
        self.assertEqual(issue(self.db, "t1", signer="alice"), "signer_domain_conflict")
        self.assertEqual(issue(self.db, "t1", signer="bob"), 60)
        self.assertEqual(close(self.db, "inv-2", signer="bob"), "signer_domain_conflict")
        self.assertEqual(self.charges("t1")[0]["signer"], "bob")

    def test_power_failure_retry_replays_recorded_result(self):
        args = {"page": "v1:p1", "rows": PAGE}
        self.assertEqual(apply_command(self.db, "meter.import_page", args, "req-1"), "captured")
        # 断电重试：同一 request_id 只回放已记录结果，不重复采录。
        self.assertEqual(apply_command(self.db, "meter.import_page", args, "req-1"), "captured")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM meter_rows")["n"], 2)
        self.assertEqual(apply_command(self.db, "billing.issue",
                                       {"tenant": "t1"}, "req-2"), 60)
        self.assertEqual(apply_command(self.db, "billing.issue",
                                       {"tenant": "t1"}, "req-2"), 60)
        self.assertEqual(len(self.charges("t1")), 1)
        # 失败命令不留命令事件也不留状态，可用新请求号安全重试。
        with self.assertRaises(ValueError):
            apply_command(self.db, "meter.import_page",
                          {"page": "v2:p1", "rows": [{"host": "h"}]}, "req-3")
        self.assertIsNone(one(self.db, "SELECT request_id FROM command_events "
                                      "WHERE request_id='req-3'"))
        self.assertIsNone(one(self.db, "SELECT id FROM meter_pages WHERE id='v2:p1'"))
        self.assertEqual(apply_command(self.db, "meter.import_page",
                                       {"page": "v2:p1", "rows": [PAGE[0]]}, "req-4"),
                         "captured")

    def test_failed_batch_leaves_no_half_ledger(self):
        self.assertEqual(dispatch(self.db, "vendor"), "no_open_batch")
        self.assertEqual(dispatch(self.db, "tenant"), "no_open_batch")
        self.assertEqual(import_page(self.db, "v1:p1", PAGE), "captured")
        self.assertEqual(close(self.db, "inv-1"), 90)
        self.assertEqual(dispatch(self.db, "vendor"), "vendor-batch-1")
        self.assertEqual(dispatch(self.db, "vendor"), "no_open_batch")
        # 批次封盘后晚到纸页只能开新批次补差，旧回单不动。
        self.assertEqual(import_page(self.db, "v1:p2", [
            {"host": "hostC", "tenant": "t3", "minute": 11, "core_seconds": 15}]), "captured")
        self.assertEqual(close(self.db, "inv-2"), 15)
        payables = rows(self.db, "SELECT invoice,core_seconds,kind,batch FROM vendor_payables "
                                 "ORDER BY rowid")
        self.assertEqual([(p["invoice"], p["core_seconds"], p["kind"], p["batch"]) for p in payables],
                         [("inv-1", 90, "initial", "vendor-batch-1"),
                          ("inv-2", 15, "supplementary", "vendor-batch-2")])
        self.assertEqual(one(self.db, "SELECT status FROM payment_batch "
                                     "WHERE id='vendor-batch-1'")["status"], "sent")

    def test_audit_replay_covers_billing_chain(self):
        # 全部经命令入口落账，审计才能从 command_events 重放整本账。
        page = {"page": "v1:p1", "rows": PAGE}
        dupe = {"page": "v2:p1", "rows": [PAGE[0]]}
        commands = [
            ("meter.import_page", page),
            ("meter.import_page", dupe),
            ("meter.calibrate", {"cal_id": "cal1", "source": "controller",
                                 "cells": [{"host": "hostA", "minute": 10, "core_seconds": 60},
                                           {"host": "hostB", "minute": 10, "core_seconds": 30}],
                                 "declared_total": 90}),
            ("meter.container", {"barcode": "CNTR-8842-1001", "tenant": "t1"}),
            ("meter.container", {"barcode": "CNTR-8842-1002", "tenant": "t2"}),
            ("meter.migrate", {"migration_id": "m1", "host": "hostA",
                               "barcode": "CNTR-8842-10", "from_minute": 10, "to_minute": 10}),
            ("meter.migrate", {"migration_id": "m2", "host": "hostB",
                               "barcode": "CNTR-8842-1002", "from_minute": 10, "to_minute": 10}),
            ("billing.close", {"invoice": "inv-1", "signer": "procurement"}),
            ("billing.issue", {"tenant": "t2", "signer": "billing"}),
            ("billing.issue", {"tenant": "t1", "signer": "billing"}),
            ("billing.dispatch", {"kind": "tenant"}),
            ("meter.migrate", {"migration_id": "m1", "host": "hostA",
                               "barcode": "CNTR-8842-1001", "from_minute": 10, "to_minute": 10}),
            ("billing.issue", {"tenant": "t1", "signer": "billing"}),
            ("billing.reconcile", {}),
        ]
        for index, (operation, arguments) in enumerate(commands, 1):
            apply_command(self.db, operation, arguments, f"cmd-{index}")
        result = audit(self.db)
        self.assertTrue(result["verified"], result["mismatches"])
        # 篡改派生归属必须被重放发现。
        self.db.execute("UPDATE attribution SET tenant='t2' WHERE host='hostA'")
        result = audit(self.db)
        self.assertFalse(result["verified"])
        self.assertTrue(any(item.get("table") == "attribution"
                            for item in result["mismatches"]))

    def test_billing_fixture_runs_through_cli_with_audit(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        output = run(str(pathlib.Path(self.temp.name) / "fixture.sqlite"),
                     root / "fixtures" / "billing_normal.json", "billing")
        results = [item["result"] for item in output["results"]]
        self.assertEqual(results, ["captured", "captured", "accepted", "accepted",
                                   "accepted", "recorded", "recorded", 90, 30, 0,
                                   "vendor-batch-1", "tenant-batch-1", "refined", 60,
                                   output["results"][-1]["result"]])
        final = output["results"][-1]["result"]
        self.assertEqual((final["vendor_posted"], final["tenant_posted"], final["held"]),
                         (90, 90, 0))
        self.assertTrue(output["audit"]["verified"], output["audit"]["mismatches"])


if __name__ == "__main__":
    unittest.main()
