"""物理用量识别模块。

把纸面计量行还原成物理事实：同一物理宿主在同一分钟的实耗只算一次，
跨门户复抄、宿主别名、虚机迁移都不创造额外核秒；计量总量须同独立
控制器原件守恒。租户归属只在所有相容迁移历史都能证明时才确认，
否则挂起等待补证；已发生的真实总耗用不因此免除供应商付款责任。

派生状态（physical_usage、attribution）全部由原始证据确定性重算，
因此审计入口可以从 command_events 重放整本账。
"""
import hashlib
import json

from .store import ensure_billing, one, rows, tx

# 控制器与门户共同校时允许的最大偏差（分钟）。超过即拒绝该批校准。
MAX_CLOCK_SKEW = 1


def canonical(db, host):
    """沿宿主别名链解析到规范物理宿主名（带环路保护）。"""
    for _ in range(8):
        alias = one(db, "SELECT canonical FROM host_alias WHERE alias=?", (host,))
        if not alias or alias["canonical"] == host:
            return host
        host = alias["canonical"]
    return host


def rebuild(db):
    """从原始证据重算物理用量与租户归属。

    物理单元 = (规范宿主, 分钟)。同一单元多次出现且核秒一致是复抄，
    去重；核秒不一致是物理读数冲突，抛错并由外层事务整体回滚，
    不留半本账。网页租户栏只是标签：多页标签不一致时标签作废，
    只能等迁移证据定归属。
    """
    ensure_billing(db)
    cells = {}
    for row in rows(db, "SELECT host,tenant,minute,core_seconds FROM meter_rows"):
        key = (canonical(db, row["host"]), row["minute"])
        cell = cells.setdefault(key, {"core_seconds": row["core_seconds"], "labels": set()})
        if cell["core_seconds"] != row["core_seconds"]:
            raise ValueError("physical_reading_conflict")
        cell["labels"].add(row["tenant"])
    db.execute("DELETE FROM physical_usage")
    db.execute("DELETE FROM attribution")
    migrations = rows(db, "SELECT * FROM migration")
    containers = rows(db, "SELECT * FROM container")
    for (host, minute), cell in sorted(cells.items()):
        label = cell["labels"].pop() if len(cell["labels"]) == 1 else None
        db.execute("INSERT INTO physical_usage VALUES(?,?,?,?)",
                   (host, minute, cell["core_seconds"], label))
        covering = [m for m in migrations
                    if canonical(db, m["host"]) == host
                    and m["from_minute"] <= minute <= m["to_minute"]]
        if covering:
            # 候选租户 = 所有覆盖该单元的迁移条码所能匹配的容器租户并集。
            # 缺末四位的条码同时匹配多家租户时，存在彼此相容但归属不同
            # 的迁移历史，用量必须挂起；匹配不到注册容器同样无法证明归属。
            tenants = set()
            for mig in covering:
                tenants |= {c["tenant"] for c in containers
                            if c["barcode"].startswith(mig["barcode"])}
            if len(tenants) == 1:
                status, tenant = "confirmed", next(iter(tenants))
            else:
                status, tenant = "held", None
        elif label is not None:
            # 没有任何迁移证据时，扫描原件上的租户栏是唯一未被挑战的归属。
            status, tenant = "confirmed", label
        else:
            status, tenant = "held", None
        db.execute("INSERT INTO attribution VALUES(?,?,?,?,?)",
                   (host, minute, tenant, status, cell["core_seconds"]))


def alias(db, name, canonical_host):
    """登记宿主别名：门户上报名 -> 规范物理宿主名。"""
    ensure_billing(db)
    with tx(db):
        old = one(db, "SELECT canonical FROM host_alias WHERE alias=?", (name,))
        if old:
            if old["canonical"] != canonical_host:
                raise ValueError("host_alias_conflict")
            return "replayed"
        db.execute("INSERT INTO host_alias VALUES(?,?)", (name, canonical_host))
        rebuild(db)
        return "accepted"


def _register_container(db, barcode, tenant, stage_id, replica):
    old = one(db, "SELECT * FROM container WHERE barcode=?", (barcode,))
    if old:
        if old["tenant"] != tenant:
            raise ValueError("container_identity_conflict")
        if stage_id and not old["stage_id"]:
            db.execute("UPDATE container SET stage_id=?,replica=? WHERE barcode=?",
                       (stage_id, replica, barcode))
            rebuild(db)
            return "accepted"
        return "replayed"
    db.execute("INSERT INTO container VALUES(?,?,?,?)", (barcode, tenant, stage_id, replica))
    rebuild(db)
    return "accepted"


def container(db, barcode, tenant):
    """按部署清单注册容器完整条码及其租户。"""
    ensure_billing(db)
    with tx(db):
        return _register_container(db, barcode, tenant, None, None)


def deploy_proof(db, barcode, tenant, stage_id, replica):
    """用发行侧证据注册容器：阶段固定成员加回执证明该副本确实部署过，
    把发行窗与部署副本串进计量归属链。"""
    ensure_billing(db)
    with tx(db):
        if not one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='member'"):
            return "deployment_not_proven"
        member = one(db, "SELECT * FROM member WHERE stage_id=? AND replica=?",
                     (stage_id, replica))
        ack = one(db, "SELECT id FROM receipt WHERE stage_id=? AND replica=?",
                  (stage_id, replica)) if member else None
        if not member or not ack:
            return "deployment_not_proven"
        return _register_container(db, barcode, tenant, stage_id, replica)


def migrate(db, migration_id, host, barcode, from_minute, to_minute):
    """登记迁移观测：条码（可能缺末四位）所示容器在 [from,to] 分钟内位于宿主。

    同 id 重放原样返回；同 id 且条码是旧条码的延伸（补到完整条码）时
    精化原观测并重算归属——迁移观测是证据不是回单，精化不改旧账，
    账务影响只通过后续补票/冲回产生。其余同 id 异内容视为身份冲突。
    """
    ensure_billing(db)
    if type(from_minute) is not int or type(to_minute) is not int:
        raise ValueError("invalid_migration")
    with tx(db):
        old = one(db, "SELECT * FROM migration WHERE id=?", (migration_id,))
        if old:
            same = (old["host"], old["barcode"], old["from_minute"], old["to_minute"]) == \
                   (host, barcode, from_minute, to_minute)
            if same:
                return "replayed"
            refined = old["host"] == host and old["from_minute"] == from_minute \
                and old["to_minute"] == to_minute and barcode.startswith(old["barcode"])
            if not refined:
                raise ValueError("migration_identity_conflict")
            db.execute("UPDATE migration SET barcode=? WHERE id=?", (barcode, migration_id))
            rebuild(db)
            return "refined"
        if from_minute > to_minute:
            return "invalid_migration_window"
        db.execute("INSERT INTO migration VALUES(?,?,?,?,?)",
                   (migration_id, host, barcode, from_minute, to_minute))
        rebuild(db)
        return "recorded"


def calibrate(db, cal_id, source, cells, declared_total, skew=0):
    """登记独立控制器的共同校时校准批。

    skew = 控制器时钟 - 门户时钟（分钟），归一化到门户时间轴后存储；
    |skew| 超过 MAX_CLOCK_SKEW 拒绝。declared_total 是控制器自证的
    总量校验和，与明细不符即拒绝。守恒核对在供应商结账时进行。
    """
    ensure_billing(db)
    if not isinstance(cells, list) or any(
            not isinstance(c, dict) or set(c) != {"host", "minute", "core_seconds"}
            or type(c["minute"]) is not int or type(c["core_seconds"]) is not int
            or c["core_seconds"] < 0 for c in cells):
        raise ValueError("invalid_calibration")
    if type(skew) is not int or type(declared_total) is not int:
        raise ValueError("invalid_calibration")
    if len({(c["host"], c["minute"]) for c in cells}) != len(cells):
        raise ValueError("invalid_calibration")
    digest = hashlib.sha256(json.dumps(
        {"cells": cells, "source": source, "total": declared_total, "skew": skew},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with tx(db):
        prior = one(db, "SELECT digest FROM calibration WHERE id=?", (cal_id,))
        if prior:
            if prior["digest"] != digest:
                raise ValueError("calibration_conflict")
            return "replayed"
        if abs(skew) > MAX_CLOCK_SKEW:
            return "calibration_skew_exceeded"
        if sum(c["core_seconds"] for c in cells) != declared_total:
            return "calibration_total_mismatch"
        db.execute("INSERT INTO calibration VALUES(?,?,?,?)", (cal_id, source, skew, digest))
        for c in cells:
            db.execute("INSERT INTO controller_cell VALUES(?,?,?,?)",
                       (cal_id, c["host"], c["minute"] - skew, c["core_seconds"]))
        return "accepted"


def _controller_cells(db):
    """控制器证明的物理单元 -> 核秒；控制器自相矛盾时返回冲突码。"""
    cells = {}
    for row in rows(db, "SELECT host,minute,core_seconds FROM controller_cell"):
        key = (canonical(db, row["host"]), row["minute"])
        if key in cells and cells[key] != row["core_seconds"]:
            return "controller_divergence:%s@%s" % key
        cells[key] = row["core_seconds"]
    return cells


def conservation(db):
    """核对计量总量与控制器原件守恒。返回 None 或分歧结果码。"""
    ctrl = _controller_cells(db)
    if isinstance(ctrl, str):
        return ctrl
    physical = {(r["host"], r["minute"]): r["core_seconds"]
                for r in rows(db, "SELECT host,minute,core_seconds FROM physical_usage")}
    for key, value in ctrl.items():
        if key in physical and physical[key] != value:
            return "controller_divergence:%s@%s" % key
    return None


def physical_total(db):
    """供应商应付所依据的真实总耗用：扫描识别的物理单元，加上控制器
    证明存在但纸页尚未送达的单元——已发生的真实耗用必须建付款责任。"""
    ctrl = _controller_cells(db)
    if isinstance(ctrl, str):
        return None
    physical = {(r["host"], r["minute"]): r["core_seconds"]
                for r in rows(db, "SELECT host,minute,core_seconds FROM physical_usage")}
    for key, value in ctrl.items():
        physical.setdefault(key, value)
    return sum(physical.values())


def confirmed_total(db, tenant):
    """该租户在所有相容迁移历史中都能证明属于自己的核秒合计。"""
    return one(db, "SELECT COALESCE(SUM(core_seconds),0) AS s FROM attribution "
                   "WHERE status='confirmed' AND tenant=?", (tenant,))["s"]


def _current_batch(db, kind):
    batch = one(db, "SELECT * FROM payment_batch WHERE kind=? AND status='open'", (kind,))
    if batch:
        return batch["id"]
    seq = one(db, "SELECT COUNT(*) AS n FROM payment_batch WHERE kind=?", (kind,))["n"]
    batch_id = "%s-batch-%s" % (kind, seq + 1)
    db.execute("INSERT INTO payment_batch VALUES(?,?,'open')", (batch_id, kind))
    return batch_id


def _sent_batch_exists(db, kind):
    return one(db, "SELECT id FROM payment_batch WHERE kind=? AND status='sent' LIMIT 1",
               (kind,)) is not None


def entry_kind(db, ledger_kind, amount):
    """晚到凭条只能产生追索/补票/冲回单：批次发出后的正额是补票，
    负额是冲回（供应商侧即追索单）；绝不修改旧回单。"""
    if amount < 0:
        return "reversal"
    return "supplementary" if _sent_batch_exists(db, ledger_kind) else "initial"


def signer_conflict(db, signer, ledger_kind):
    """采购与客户账务须为独立签发人：同一具名签发人不得跨两本账。"""
    if signer is None:
        return False
    other = "tenant_charges" if ledger_kind == "vendor" else "vendor_payables"
    return one(db, "SELECT 1 AS x FROM %s WHERE signer=? LIMIT 1" % other,
               (signer,)) is not None


def dispatch(db, kind):
    """把当前开口批次发往银行。批次封盘后只读，后续更正只能开新批次。
    单条 UPDATE 处于外层事务内，失败即整体回滚，不留半本账。"""
    ensure_billing(db)
    with tx(db):
        if kind not in ("vendor", "tenant"):
            return "unknown_ledger"
        batch = one(db, "SELECT * FROM payment_batch WHERE kind=? AND status='open'", (kind,))
        if not batch:
            return "no_open_batch"
        db.execute("UPDATE payment_batch SET status='sent' WHERE id=?", (batch["id"],))
        return batch["id"]


def reconcile(db):
    """两本账对账视图：物理总量 = 已确证 + 挂起；供应商应付另含控制器
    证明但纸页未到的部分。两本账独立签发，差额即未归属挂起量。"""
    ensure_billing(db)
    with tx(db):
        confirmed = one(db, "SELECT COALESCE(SUM(core_seconds),0) AS s FROM attribution "
                            "WHERE status='confirmed'")["s"]
        held = one(db, "SELECT COALESCE(SUM(core_seconds),0) AS s FROM attribution "
                       "WHERE status='held'")["s"]
        posted_vendor = one(db, "SELECT COALESCE(SUM(core_seconds),0) AS s FROM vendor_payables")["s"]
        posted_tenant = one(db, "SELECT COALESCE(SUM(core_seconds),0) AS s FROM tenant_charges")["s"]
        due = physical_total(db)
        return {"confirmed": confirmed, "held": held,
                "physical": confirmed + held,
                "controller_attested": None if due is None else due - confirmed - held,
                "vendor_due": due, "vendor_posted": posted_vendor,
                "tenant_posted": posted_tenant,
                "unbilled_confirmed": confirmed - posted_tenant}
