"""外部系统的进程内幂等模拟器。

现场的交换机、容器编排器和通知网关不属于 SQLite 控制面：本地库断电后，
真正发生过的动作只能凭外部系统保存的幂等回执恢复。本类模拟这些外部权威，
同一 request_id 永远只产生一次外部效果，并保留完整回执台账。
"""
from __future__ import annotations

from .evidence import deterministic_id


class ExternalFabric:
    def __init__(self, notice_timeout_times=0):
        self.rules = {}
        self.session_clears = {}
        self.migrations = {}
        self.moves = {}
        self.revokes = {}
        self.notices = {}
        self._ledger = []
        self.notice_timeout_times = notice_timeout_times
        self.notice_attempts = {}

    # -- 台账 -------------------------------------------------------------
    def _record(self, receipt):
        self._ledger.append(receipt)
        return receipt

    def ledger(self):
        return list(self._ledger)

    def receipts(self):
        return list(self._ledger)

    def receipts_for(self, request_id):
        return [r for r in self._ledger if r.get("request_id") == request_id]

    # -- 交换机 -----------------------------------------------------------
    def install_edge_rule(self, request_id, edge, spec="deny_egress_all"):
        if request_id in self.rules:
            return self.rules[request_id]
        receipt = {
            "receipt_id": deterministic_id("swr", request_id),
            "request_id": request_id, "system": "switch",
            "kind": "rule_effective", "status": "effective", "confirmed": True,
            "edge": edge, "rule_spec": spec,
        }
        self.rules[request_id] = receipt
        return self._record(receipt)

    install_rule = install_edge_rule

    def clear_edge_sessions(self, request_id, edge=None, session_id=None, count=None):
        if request_id in self.session_clears:
            return self.session_clears[request_id]
        if count is None:
            count = 1 if session_id else 2
        receipt = {
            "receipt_id": deterministic_id("swc", request_id),
            "request_id": request_id, "system": "switch",
            "kind": "sessions_cleared", "status": "confirmed", "confirmed_flag": True,
            "edge": edge, "session_id": session_id, "cleared_count": count,
        }
        receipt["confirmed"] = True
        self.session_clears[request_id] = receipt
        return self._record(receipt)

    clear_sessions = clear_edge_sessions

    # -- 容器编排 ---------------------------------------------------------
    def migrate_traffic(self, request_id, container, workloads=None):
        if request_id in self.migrations:
            return self.migrations[request_id]
        receipt = {"receipt_id": deterministic_id("cmr", request_id),
                   "request_id": request_id, "system": "container",
                   "kind": "traffic_migrated", "status": "confirmed", "confirmed": True,
                   "container": container, "workloads": list(workloads or [])}
        self.migrations[request_id] = receipt
        return self._record(receipt)

    def move_to_forensics(self, request_id, container, network="forensics"):
        if request_id in self.moves:
            return self.moves[request_id]
        receipt = {"receipt_id": deterministic_id("cmv", request_id),
                   "request_id": request_id, "system": "container",
                   "kind": "move_forensics", "status": "confirmed", "confirmed": True,
                   "container": container, "target_network": network}
        self.moves[request_id] = receipt
        return self._record(receipt)

    def revoke_egress(self, request_id, container):
        if request_id in self.revokes:
            return self.revokes[request_id]
        receipt = {"receipt_id": deterministic_id("crv", request_id),
                   "request_id": request_id, "system": "container",
                   "kind": "revoke_egress", "status": "confirmed", "confirmed": True,
                   "container": container}
        self.revokes[request_id] = receipt
        return self._record(receipt)

    # -- 通知网关 ---------------------------------------------------------
    def send_notice(self, request_id, tenant, payload=None):
        # 幂等：同一 request_id 的重试返回同一外部回执，不会产生第二封。
        if request_id in self.notices:
            return self.notices[request_id]
        attempts = self.notice_attempts.get(request_id, 0) + 1
        self.notice_attempts[request_id] = attempts
        receipt = {"receipt_id": deterministic_id("ntf", request_id),
                   "request_id": request_id, "system": "notice",
                   "kind": "notice_delivered", "status": "delivered", "confirmed": True,
                   "tenant": tenant}
        # 外部系统先落回执（实际已发），客户端这一侧却可能超时。
        self.notices[request_id] = receipt
        self._record(receipt)
        if attempts <= self.notice_timeout_times:
            raise TimeoutError("notice sent externally but client timed out")
        return receipt

    send = send_notice


# 常见别名
SwitchFabric = ExternalFabric
Fabric = ExternalFabric
ExternalSystems = ExternalFabric
