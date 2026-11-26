from .physical_usage import (confirmed_total, entry_kind, signer_conflict,
                             _current_batch)
from .store import ensure_billing, one, tx


def issue(db, tenant, signer=None):
    """租户开票（客户账务签发）。

    只就开所有相容迁移历史中都能证明属于该租户的核秒；挂起用量不开票。
    与已开回单的差额入账：批次发出后正差额为补票、负差额为冲回单，
    旧回单永不修改，错收由此产生实际资金冲正。返回本次入账差额。
    """
    ensure_billing(db)
    with tx(db):
        if signer_conflict(db, signer, 'tenant'):
            return 'signer_domain_conflict'
        confirmed = confirmed_total(db, tenant)
        posted = one(db, 'SELECT COALESCE(SUM(core_seconds),0) AS s FROM tenant_charges '
                         'WHERE tenant=?', (tenant,))['s']
        delta = confirmed - posted
        if delta == 0:
            return 0
        db.execute('INSERT INTO tenant_charges(tenant,core_seconds,kind,batch,signer) '
                   'VALUES (?,?,?,?,?)',
                   (tenant, delta, entry_kind(db, 'tenant', delta),
                    _current_batch(db, 'tenant'), signer))
        return delta
