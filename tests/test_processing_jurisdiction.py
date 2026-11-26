import itertools
import json
import pathlib
import tempfile
import unittest

from cloudroll.cli import apply_command, audit
from cloudroll.store import open_db, one, rows


class ProcessingJurisdiction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.temp.name) / "jurisdiction.sqlite"))
        self.sequence = itertools.count(1)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def do(self, operation, **arguments):
        ordinal = next(self.sequence)
        if operation in ("artifact.plan", "artifact.revoke"):
            arguments.setdefault("event_id", f"decision-{ordinal}")
        return apply_command(self.db, operation, arguments, f"command-{ordinal}")

    def assert_audit(self):
        result = audit(self.db)
        self.assertTrue(result["verified"], result["mismatches"])

    def release(self):
        # 固定场景:服务 S 计划窗第10至30分钟,制品 A 合格,东西两区固定副本第12分钟回执与健康齐全
        self.do("artifact.baseline", service="S", api=3, generation=1)
        self.do("artifact.register", artifact_id="A", digest="hashA", min_api=2, max_api=4)
        self.do("artifact.contract", artifact_id="A", min_protocol=1, max_protocol=3)
        self.do("artifact.population", service="S", protocol=1, count=5)
        self.assertEqual(self.do("artifact.plan", plan_id="P", service="S", artifact_id="A",
                                 start_ts=10, end_ts=30), "locked")
        self.assertEqual(self.do("stage.start", stage_id="ST", plan_id="P",
                                 members=[{"replica": "east-1", "generation": 1},
                                          {"replica": "west-1", "generation": 1}],
                                 start_ts=10, end_ts=30), "started")
        for replica in ("east-1", "west-1"):
            self.do("stage.receipt", receipt_id="rc-" + replica, stage_id="ST", replica=replica,
                    generation=1, digest="hashA")
            self.do("stage.sample", sample_id="hb-" + replica, stage_id="ST", replica=replica,
                    at=12, digest="hashA", healthy=True)
        self.assertEqual(self.do("stage.decide", stage_id="ST", at=12), "passed")

    def permit(self, permit_id="C", until=25):
        return self.do("permit.grant", permit_id=permit_id, customer="customer-C",
                       categories=["telemetry"], purposes=["billing"], zones=["east"],
                       valid_from=0, valid_until=until, withdrawal="immediate")

    def receive(self, request_id="R", permit_id="C", at=18, entry_zone="west",
                entry_kind="cache", plan_id="P", category="telemetry", purpose="billing"):
        return self.do("custody.receive", request_id=request_id, permit_id=permit_id,
                       plan_id=plan_id, input_commitment="commit-" + request_id,
                       category=category, purpose=purpose, at=at,
                       entry_zone=entry_zone, entry_kind=entry_kind)

    def east_chain(self, request_id="R", permit_id="C", attest_device="east-1",
                   attest_zone="east"):
        # 第18分钟密文进入西区缓存,第19分钟东区密钥服务释放一次设备绑定解密权
        self.assertEqual(self.receive(request_id, permit_id), "accepted")
        self.assertEqual(self.do("custody.key_release", release_id="K-" + request_id,
                                 request_id=request_id, zone="east", device="east-1", at=19,
                                 permit_version=1), "released")
        self.assertEqual(self.do("custody.attest", attestation_id="AT-" + request_id,
                                 request_id=request_id, release_id="K-" + request_id,
                                 device=attest_device, zone=attest_zone, at=19,
                                 input_commitment="commit-" + request_id,
                                 output_commitment="out-" + request_id,
                                 recipient="client-C", permit_version=1), "recorded")

    def deliver(self, request_id="R", at=20):
        return self.do("custody.deliver", delivery_id="D-" + request_id, request_id=request_id,
                       output_commitment="out-" + request_id, recipient="client-C", at=at)

    def violations(self, request_id="R"):
        return rows(self.db, "SELECT * FROM violation WHERE request_id=? ORDER BY id",
                    (request_id,))

    def test_east_compute_with_west_ciphertext_work_is_compliant(self):
        self.release()
        self.permit()
        self.east_chain("R")
        self.assertEqual(self.deliver("R"), "delivered:compliant")
        proof = one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'")
        self.assertEqual(proof["method"], "ciphertext_assist")
        self.assertEqual(json.loads(proof["zones"]), ["east"])
        self.assertEqual(json.loads(proof["devices"]), ["east-1"])
        self.assertEqual(proof["status"], "issued")
        self.assertEqual(proof["permit_version"], 1)
        self.assertEqual(self.violations("R"), [])
        # 阶段结论不受请求层影响,两种执行办法下阶段都通过
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='ST'")["status"], "passed")
        self.assert_audit()

    def test_west_accelerator_key_misuse_is_not_disguised_as_method_two(self):
        self.release()
        self.permit()
        # 设备原件证明西区加速器实际拿到了绑定给东区节点的解密权
        self.east_chain("R", attest_device="west-accel-9", attest_zone="west")
        self.assertEqual(self.deliver("R"), "delivered:violation")
        kinds = {v["kind"] for v in self.violations("R")}
        self.assertIn("key_misuse", kinds)
        self.assertIn("compute_outside_permit", kinds)
        # 交付发生了,但不能被伪装成第二种合规办法:不签发交付证明
        self.assertIsNone(one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'"))
        self.assertEqual(one(self.db, "SELECT compliance FROM delivery WHERE request_id='R'")
                         ["compliance"], "violation")
        # 通知指向具体输入与物理位置,而不是把整个阶段成员笼统判成泄漏
        misuse = one(self.db, "SELECT * FROM violation WHERE request_id='R' AND kind='key_misuse'")
        detail = json.loads(misuse["detail"])
        self.assertEqual(misuse["zone"], "west")
        self.assertEqual(detail["device"], "west-accel-9")
        self.assertEqual(detail["bound_device"], "east-1")
        self.assertEqual(detail["input"], "commit-R")
        named = {json.loads(v["detail"]).get("device") for v in self.violations("R")}
        self.assertNotIn("east-1", named)
        self.assertNotIn("west-1", named)
        self.assert_audit()

    def test_plaintext_dump_reaching_west_support_seat_is_precise_violation(self):
        self.release()
        self.permit()
        self.east_chain("R")
        # 东区节点排障生成含明文的异常转储,转储代理把副本送到西区支持席
        self.do("custody.derive", dump_id="DUMP1", request_id="R", zone="east",
                kind="exception_dump", at=19, content_class="plaintext")
        self.do("custody.transfer", transfer_id="T1", dump_id="DUMP1", to_zone="west",
                principal="west-support-seat", at=19)
        # 主执行链每个签名都正确,但交付不能声称"仅在东区处理"
        self.assertEqual(self.deliver("R"), "delivered:violation")
        self.assertIsNone(one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'"))
        notice = one(self.db, "SELECT * FROM violation WHERE request_id='R' "
                              "AND kind='plaintext_dump_exposure'")
        detail = json.loads(notice["detail"])
        self.assertEqual(notice["zone"], "west")
        self.assertEqual(notice["evidence"], "T1")
        self.assertEqual(detail["principal"], "west-support-seat")
        self.assertEqual(detail["dump"], "DUMP1")
        self.assertEqual(detail["input"], "commit-R")
        self.assertEqual([v["kind"] for v in self.violations("R")], ["plaintext_dump_exposure"])
        self.assert_audit()

    def test_ciphertext_only_dump_cross_region_remains_legitimate(self):
        self.release()
        self.permit()
        self.east_chain("R")
        # 另一份转储只含加密堆栈,传输区域与外部文件名相同,不得被错杀
        self.do("custody.derive", dump_id="DUMP2", request_id="R", zone="east",
                kind="exception_dump", at=19, content_class="ciphertext")
        self.do("custody.transfer", transfer_id="T2", dump_id="DUMP2", to_zone="west",
                principal="west-support-seat", at=19)
        self.assertEqual(self.deliver("R"), "delivered:compliant")
        self.assertEqual(self.violations("R"), [])
        proof = one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'")
        self.assertEqual(proof["status"], "issued")
        self.assert_audit()

    def test_missing_dump_evidence_keeps_delivery_pending_until_classification(self):
        self.release()
        self.permit()
        self.east_chain("R")
        self.do("custody.derive", dump_id="DUMP1", request_id="R", zone="east",
                kind="exception_dump", at=19, content_class="unknown")
        self.do("custody.transfer", transfer_id="T1", dump_id="DUMP1", to_zone="west",
                principal="west-support-seat", at=19)
        # 证据暂缺:结果已交付,合规结论待定
        self.assertEqual(self.deliver("R"), "delivered:pending")
        self.assertIsNone(one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'"))
        self.assertEqual(one(self.db, "SELECT status FROM request WHERE id='R'")["status"],
                         "delivered")
        # 后补凭据证明只含密文:签发有效交付证明
        self.assertEqual(self.do("custody.classify", class_id="CL1", dump_id="DUMP1",
                                 content_class="ciphertext", at=21), "recorded")
        proof = one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'")
        self.assertEqual(proof["status"], "issued")
        self.assertEqual(one(self.db, "SELECT compliance FROM request WHERE id='R'")["compliance"],
                         "compliant")
        # 同一形态若后补为明文:产生精确违规通知而非交付证明
        self.east_chain("R2")
        self.do("custody.derive", dump_id="DUMP2", request_id="R2", zone="east",
                kind="exception_dump", at=19, content_class="unknown")
        self.do("custody.transfer", transfer_id="T2", dump_id="DUMP2", to_zone="west",
                principal="west-support-seat", at=19)
        self.assertEqual(self.deliver("R2"), "delivered:pending")
        self.assertEqual(self.do("custody.classify", class_id="CL2", dump_id="DUMP2",
                                 content_class="plaintext", at=21), "recorded")
        self.assertEqual(one(self.db, "SELECT compliance FROM request WHERE id='R2'")
                         ["compliance"], "violation")
        self.assertIsNone(one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R2'"))
        kinds = {v["kind"] for v in self.violations("R2")}
        self.assertEqual(kinds, {"plaintext_dump_exposure"})
        self.assert_audit()

    def test_late_device_attestation_resolves_pending_delivery(self):
        self.release()
        self.permit()
        self.assertEqual(self.receive("R"), "accepted")
        self.do("custody.key_release", release_id="K-R", request_id="R", zone="east",
                device="east-1", at=19, permit_version=1)
        # 设备签收未到:交付保持待定
        self.assertEqual(self.deliver("R"), "delivered:pending")
        self.assertIsNone(one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'"))
        # 晚到的设备证明确认东区计算:补发有效交付证明
        self.assertEqual(self.do("custody.attest", attestation_id="AT-R", request_id="R",
                                 release_id="K-R", device="east-1", zone="east", at=19,
                                 input_commitment="commit-R", output_commitment="out-R",
                                 recipient="client-C", permit_version=1), "recorded")
        proof = one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'")
        self.assertEqual(proof["status"], "issued")
        self.assertEqual(proof["method"], "ciphertext_assist")
        # 晚到证明也可能揭示违规加速器
        self.assertEqual(self.receive("R2"), "accepted")
        self.do("custody.key_release", release_id="K-R2", request_id="R2", zone="east",
                device="east-1", at=19, permit_version=1)
        self.assertEqual(self.deliver("R2"), "delivered:pending")
        self.do("custody.attest", attestation_id="AT-R2", request_id="R2", release_id="K-R2",
                device="west-accel-9", zone="west", at=19, input_commitment="commit-R2",
                output_commitment="out-R2", recipient="client-C", permit_version=1)
        self.assertEqual(one(self.db, "SELECT compliance FROM request WHERE id='R2'")
                         ["compliance"], "violation")
        self.assertIsNone(one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R2'"))
        self.assert_audit()

    def test_late_dump_evidence_supersedes_issued_proof(self):
        self.release()
        self.permit()
        self.east_chain("R")
        self.assertEqual(self.deliver("R"), "delivered:compliant")
        self.assertEqual(one(self.db, "SELECT status FROM delivery_proof WHERE request_id='R'")
                         ["status"], "issued")
        # 交付后才补录的转储证据揭示西区明文接触:证明保留但标记取代,另发违规通知
        self.do("custody.derive", dump_id="DUMP1", request_id="R", zone="east",
                kind="exception_dump", at=19, content_class="plaintext")
        self.do("custody.transfer", transfer_id="T1", dump_id="DUMP1", to_zone="west",
                principal="west-support-seat", at=19)
        self.assertEqual(one(self.db, "SELECT status FROM delivery_proof WHERE request_id='R'")
                         ["status"], "superseded")
        self.assertEqual(one(self.db, "SELECT compliance FROM request WHERE id='R'")["compliance"],
                         "violation")
        self.assertEqual([v["kind"] for v in self.violations("R")], ["plaintext_dump_exposure"])
        self.assert_audit()

    def test_permit_withdrawal_halts_pending_work_and_disposes_intermediates(self):
        self.release()
        self.permit()
        self.assertEqual(self.receive("R"), "accepted")
        self.do("custody.hop", hop_id="HQ", request_id="R", kind="queue", zone="east", at=18)
        self.do("custody.key_release", release_id="K-R", request_id="R", zone="east",
                device="east-1", at=19, permit_version=1)
        self.do("custody.derive", dump_id="DUMP1", request_id="R", zone="east",
                kind="exception_dump", at=19, content_class="plaintext")
        self.assertEqual(self.do("permit.withdraw", permit_id="C", at=20), "withdrawn")
        self.assertEqual(self.do("permit.withdraw", permit_id="C", at=20), "already_withdrawn")
        # 尚未开始的明文工作停止:不能新取密钥、不能交付
        self.assertEqual(one(self.db, "SELECT status FROM request WHERE id='R'")["status"],
                         "halted")
        self.assertEqual(self.do("custody.key_release", release_id="K2", request_id="R",
                                 zone="east", device="east-1", at=21, permit_version=1),
                         "request_halted")
        self.assertEqual(self.deliver("R", at=21), "request_halted")
        self.assertEqual(self.receive("R2", at=21), "permit_not_valid")
        # 未交付的中间物按所在法域分别封存或销毁
        disposal = {d["holding"]: (d["zone"], d["method"])
                    for d in rows(self.db, "SELECT * FROM disposal WHERE request_id='R'")}
        self.assertEqual(disposal["hop-R-entry"], ("west", "destroyed"))
        self.assertEqual(disposal["HQ"], ("east", "sealed"))
        self.assertEqual(disposal["DUMP1"], ("east", "sealed"))
        # 撤回竞态:撤回前已完成的合法计算凭据追加保留,撤回时刻起的计算记为违规
        self.assertEqual(self.do("custody.attest", attestation_id="AT-old", request_id="R",
                                 release_id="K-R", device="east-1", zone="east", at=19,
                                 input_commitment="commit-R", output_commitment="out-R",
                                 recipient="client-C", permit_version=1), "recorded")
        self.assertEqual(self.violations("R"), [])
        self.do("custody.attest", attestation_id="AT-late", request_id="R", release_id="K-R",
                device="east-1", zone="east", at=20, input_commitment="commit-R",
                output_commitment="out-R", recipient="client-C", permit_version=1)
        kinds = {v["kind"] for v in self.violations("R")}
        self.assertEqual(kinds, {"compute_without_permit"})
        self.assert_audit()

    def test_withdrawal_preserves_delivered_proof_and_processed_set(self):
        self.release()
        self.permit()
        self.east_chain("R")
        self.assertEqual(self.deliver("R"), "delivered:compliant")
        self.assertEqual(self.do("permit.withdraw", permit_id="C", at=21), "withdrawn")
        # 已交付的合法结果保留原交付证明,已处理集合不变
        request = one(self.db, "SELECT * FROM request WHERE id='R'")
        self.assertEqual(request["status"], "delivered")
        self.assertEqual(request["compliance"], "compliant")
        self.assertEqual(one(self.db, "SELECT status FROM delivery_proof WHERE request_id='R'")
                         ["status"], "issued")
        # 已交付请求的未交付中间物同样按法域处置
        disposal = {d["holding"]: d["method"]
                    for d in rows(self.db, "SELECT * FROM disposal WHERE request_id='R'")}
        self.assertEqual(disposal, {"hop-R-entry": "destroyed"})
        # 迟到的设备签收仍追加保留,且与断电重试、客户查询看到同一集合
        self.assertEqual(self.do("custody.attest", attestation_id="AT-late", request_id="R",
                                 release_id="K-R", device="east-1", zone="east", at=19,
                                 input_commitment="commit-R", output_commitment="out-R",
                                 recipient="client-C", permit_version=1), "recorded")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM attestation "
                                      "WHERE request_id='R'")["n"], 2)
        first = self.do("custody.query", request_id="R")
        second = self.do("custody.query", request_id="R")
        self.assertEqual(first, second)
        self.assertEqual(first["proof"]["status"], "issued")
        self.assertEqual(first["request"]["compliance"], "compliant")
        self.assert_audit()

    def test_duplicate_request_confirms_final_result_only_once(self):
        self.release()
        self.permit()
        self.east_chain("R")
        # 同一请求重复受理:幂等,不产生第二份处理记录
        self.assertEqual(self.receive("R"), "already_accepted")
        self.assertEqual(self.receive("R", category="location"), "request_identity_conflict")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM request")["n"], 1)
        # 重试或跨区转发后,最终结果只向客户确认一次
        self.assertEqual(self.deliver("R"), "delivered:compliant")
        self.assertEqual(self.deliver("R"), "already_delivered")
        self.assertEqual(self.do("custody.deliver", delivery_id="D-R-alt", request_id="R",
                                 output_commitment="other", recipient="client-C", at=21),
                         "conflicting_delivery")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM delivery")["n"], 1)
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM delivery_proof")["n"], 1)
        # 断电重试同一命令请求号:返回同一结果,状态不变
        args = dict(delivery_id="D-R2", request_id="R2", output_commitment="out-R2",
                    recipient="client-C", at=20)
        self.east_chain("R2")
        first = apply_command(self.db, "custody.deliver", args, "cmd-deliver-once")
        second = apply_command(self.db, "custody.deliver", args, "cmd-deliver-once")
        self.assertEqual(first, second)
        self.assertEqual(first, "delivered:compliant")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM delivery")["n"], 2)
        self.assert_audit()

    def test_fallback_replica_inherits_permit_restrictions(self):
        self.release()
        self.permit(until=80)
        # 同服务后续窗口内制造一个失败阶段与恢复工单
        self.assertEqual(self.do("artifact.plan", plan_id="P2", service="S", artifact_id="A",
                                 start_ts=40, end_ts=50), "locked")
        self.do("stage.start", stage_id="ST2", plan_id="P2",
                members=[{"replica": "east-1", "generation": 1}], start_ts=41, end_ts=45)
        self.assertTrue(self.do("stage.decide", stage_id="ST2", at=46).startswith("failed"))
        case = one(self.db, "SELECT * FROM recovery WHERE stage_id='ST2'")
        self.assertEqual(self.do("artifact.plan", plan_id="P3", service="S", artifact_id="A",
                                 start_ts=60, end_ts=70), "locked")
        self.assertEqual(self.receive("R", at=61, entry_zone="east", entry_kind="queue",
                                      plan_id="P3"), "accepted")
        self.assertEqual(self.do("custody.hop", hop_id="FB0", request_id="R", kind="fallback",
                                 zone="east", at=61, ref="rec-missing"), "unknown_recovery_case")
        # 回退副本在西区只做密文验证工作:沿同一处理链继承限制,合法
        self.assertEqual(self.do("custody.hop", hop_id="FB1", request_id="R", kind="fallback",
                                 zone="west", at=62, principal="west-1", ref=case["id"]),
                         "recorded")
        # 回退副本不得在西区取得明文密钥
        self.assertEqual(self.do("custody.key_release", release_id="K-W", request_id="R",
                                 zone="west", device="west-1", at=63, permit_version=1),
                         "zone_not_permitted")
        # 明文计算仍在东区完成并交付
        self.assertEqual(self.do("custody.key_release", release_id="K-R", request_id="R",
                                 zone="east", device="east-1", at=63, permit_version=1),
                         "released")
        self.do("custody.attest", attestation_id="AT-R", request_id="R", release_id="K-R",
                device="east-1", zone="east", at=63, input_commitment="commit-R",
                output_commitment="out-R", recipient="client-C", permit_version=1)
        self.assertEqual(self.deliver("R", at=64), "delivered:compliant")
        proof = one(self.db, "SELECT * FROM delivery_proof WHERE request_id='R'")
        self.assertEqual(proof["method"], "ciphertext_assist")
        self.assert_audit()

    def test_execution_credential_binds_current_permit_version(self):
        self.release()
        self.permit()
        self.assertEqual(self.receive("R"), "accepted")
        # 许可在第19分钟修订为版本2
        self.assertEqual(self.do("permit.grant", permit_id="C", customer="customer-C",
                                 categories=["telemetry"], purposes=["billing"], zones=["east"],
                                 valid_from=0, valid_until=25, withdrawal="immediate",
                                 effective_at=19), "amended")
        # 密钥服务不得按旧版本放权
        self.assertEqual(self.do("custody.key_release", release_id="K-old", request_id="R",
                                 zone="east", device="east-1", at=19, permit_version=1),
                         "stale_permit_version")
        self.assertEqual(self.do("custody.key_release", release_id="K-new", request_id="R",
                                 zone="east", device="east-1", at=19, permit_version=2),
                         "released")
        # 设备执行凭据绑定的许可版本与当时版本不符:记为违规
        self.do("custody.attest", attestation_id="AT-R", request_id="R", release_id="K-new",
                device="east-1", zone="east", at=19, input_commitment="commit-R",
                output_commitment="out-R", recipient="client-C", permit_version=1)
        self.assertEqual(self.deliver("R"), "delivered:violation")
        self.assertEqual([v["kind"] for v in self.violations("R")], ["stale_permit_version"])
        self.assert_audit()

    def test_request_acceptance_validates_permit_terms(self):
        self.release()
        self.permit()
        self.assertEqual(self.receive("R", permit_id="nope"), "unknown_permit")
        self.assertEqual(self.receive("R", plan_id="nope"), "plan_not_active")
        self.assertEqual(self.receive("R", at=5), "outside_release_window")
        self.assertEqual(self.receive("R", category="location"), "category_not_permitted")
        self.assertEqual(self.receive("R", purpose="ads"), "purpose_not_permitted")
        self.assertEqual(self.receive("R", entry_kind="compute"), "invalid_kind")
        # 许可有效期外的受理被拒绝
        self.assertEqual(self.do("permit.grant", permit_id="C2", customer="customer-C",
                                 categories=["telemetry"], purposes=["billing"], zones=["east"],
                                 valid_from=0, valid_until=15, withdrawal="immediate"), "granted")
        self.assertEqual(self.receive("R", permit_id="C2"), "permit_not_valid")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM request")["n"], 0)
        self.assert_audit()

    def test_in_zone_plaintext_dump_requires_support_authorization(self):
        self.release()
        self.permit()
        self.east_chain("R")
        self.do("custody.derive", dump_id="DUMP1", request_id="R", zone="east",
                kind="exception_dump", at=19, content_class="plaintext")
        # 明文转储在许可区内但接收人没有当时的支持授权:仍是精确违规
        self.do("custody.transfer", transfer_id="T1", dump_id="DUMP1", to_zone="east",
                principal="east-support-seat", at=19)
        self.assertEqual(self.deliver("R"), "delivered:violation")
        self.assertEqual([v["kind"] for v in self.violations("R")],
                         ["unauthorized_plaintext_access"])
        # 有支持授权的另一请求:合规交付
        self.assertEqual(self.do("permit.authorize", auth_id="AUTH1", permit_id="C",
                                 principal="east-support-seat", purpose="billing",
                                 valid_from=0, valid_until=25), "authorized")
        self.east_chain("R2")
        self.do("custody.derive", dump_id="DUMP2", request_id="R2", zone="east",
                kind="exception_dump", at=19, content_class="plaintext")
        self.do("custody.transfer", transfer_id="T2", dump_id="DUMP2", to_zone="east",
                principal="east-support-seat", at=19)
        self.assertEqual(self.deliver("R2"), "delivered:compliant")
        self.assert_audit()

    def test_plaintext_hop_outside_permit_zones_is_violation(self):
        self.release()
        self.permit()
        self.east_chain("R")
        # 加速器代执行若携带明文越区,沿处理链记为违规
        self.do("custody.hop", hop_id="ACC1", request_id="R", kind="accelerator", zone="west",
                at=19, content="plaintext", principal="west-accel-9")
        self.assertEqual(self.deliver("R"), "delivered:violation")
        reach = one(self.db, "SELECT * FROM violation WHERE request_id='R' "
                             "AND kind='plaintext_reach'")
        self.assertEqual(reach["zone"], "west")
        self.assertEqual(json.loads(reach["detail"])["principal"], "west-accel-9")
        self.assert_audit()


if __name__ == "__main__":
    unittest.main()
