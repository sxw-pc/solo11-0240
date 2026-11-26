import hashlib
import json

from .physical_usage import rebuild
from .store import ensure_billing, one, tx


def import_page(db, page, rows):
    """采录一页扫描原件。同页同内容重扫只回放原结果；内容不同即冲突。
    落账后立即重算物理用量，整页处于同一事务，失败不留半页。"""
    ensure_billing(db)
    if not isinstance(rows, list) or any(
            not isinstance(r, dict) or set(r) != {'host', 'tenant', 'minute', 'core_seconds'}
            or type(r['minute']) is not int or type(r['core_seconds']) is not int
            or r['core_seconds'] < 0 for r in rows):
        raise ValueError('invalid_meter_page')
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    with tx(db):
        prior = one(db, 'SELECT digest FROM meter_pages WHERE id=?', (page,))
        if prior:
            if prior['digest'] != digest:
                raise ValueError('meter_page_conflict')
            return 'replayed'
        db.execute('INSERT INTO meter_pages VALUES (?,?)', (page, digest))
        for i, r in enumerate(rows, 1):
            db.execute('INSERT INTO meter_rows VALUES (?,?,?,?,?,?)',
                       (page, i, r['host'], r['tenant'], r['minute'], r['core_seconds']))
        rebuild(db)
        return 'captured'
