from .physical_usage import (conservation, entry_kind, physical_total,
                             signer_conflict, _current_batch)
from .store import ensure_billing, one, tx


def close(db, invoice, signer=None):
    """供应商应付结账（采购签发）。

    应付基数是物理识别后的真实总耗用：同一物理宿主同一分钟只付一次，
    复抄、别名、迁移不加成；控制器证明而纸页未到的耗用照付。总量须同
    控制器原件守恒，分歧即拒付整批（原子，不留半本账）。同 invoice
    重试回放原回单；晚到用量只能开新票补差，不改旧回单。
    """
    ensure_billing(db)
    with tx(db):
        old = one(db, 'SELECT core_seconds FROM vendor_payables WHERE invoice=?', (invoice,))
        if old:
            return old['core_seconds']
        if signer_conflict(db, signer, 'vendor'):
            return 'signer_domain_conflict'
        divergence = conservation(db)
        if divergence:
            return divergence
        total = physical_total(db)
        posted = one(db, 'SELECT COALESCE(SUM(core_seconds),0) AS s FROM vendor_payables')['s']
        delta = total - posted
        db.execute('INSERT INTO vendor_payables VALUES (?,?,?,?,?)',
                   (invoice, delta, entry_kind(db, 'vendor', delta),
                    _current_batch(db, 'vendor'), signer))
        return delta
