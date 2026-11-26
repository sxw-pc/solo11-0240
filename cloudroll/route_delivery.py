"""Routes actually issued to devices.

A route receipt proves bytes were *sent* to a device. It is not evidence that a
human ever saw them: prefetch may only cache the bytes and the screen may never
render them. Rendered evidence lives in :mod:`cloudroll.exposure`. A route can
be withdrawn while it has no confirmed exposure; once an exposure references it
the route is frozen, because changing the digest sent to a device would
silently change the arm a registered sample belongs to.
"""
from .store import tx


def _row(db, sql, args=()):
    """Return a dict-like row even on a connection without sqlite3.Row."""
    cursor = db.execute(sql, args)
    row = cursor.fetchone()
    if row is None:
        return None
    keys = [item[0] for item in cursor.description]
    return dict(zip(keys, row))


_DDL = ("CREATE TABLE IF NOT EXISTS delivered_routes (receipt TEXT PRIMARY KEY, "
        "account TEXT NOT NULL, device TEXT NOT NULL, digest TEXT NOT NULL, "
        "session TEXT, region TEXT, status TEXT NOT NULL DEFAULT 'issued')")


def _migrate(db):
    db.execute(_DDL)
    columns = {row[1] for row in db.execute("PRAGMA table_info(delivered_routes)")}
    if "session" not in columns:
        db.execute("ALTER TABLE delivered_routes ADD COLUMN session TEXT")
    if "region" not in columns:
        db.execute("ALTER TABLE delivered_routes ADD COLUMN region TEXT")
    if "status" not in columns:
        db.execute("ALTER TABLE delivered_routes ADD COLUMN status TEXT NOT NULL DEFAULT 'issued'")


def issue(db, receipt, account, device, digest, session=None, region=None):
    with tx(db):
        _migrate(db)
        previous = _row(db, "SELECT * FROM delivered_routes WHERE receipt=?", (receipt,))
        if previous:
            if (previous["account"], previous["device"], previous["digest"],
                    previous["session"], previous["region"]) != (account, device, digest, session, region):
                raise ValueError("route_receipt_conflict")
            return "replayed"
        db.execute(
            "INSERT INTO delivered_routes(receipt,account,device,digest,session,region,status) "
            "VALUES(?,?,?,?,?,?,'issued')",
            (receipt, account, device, digest, session, region))
        return "issued"


def withdraw(db, receipt):
    """Recall a route that has not yet produced a confirmed exposure."""
    with tx(db):
        _migrate(db)
        route = _row(db, "SELECT * FROM delivered_routes WHERE receipt=?", (receipt,))
        if not route:
            return "unknown_route_receipt"
        exposed = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='exposure'").fetchone()
        if exposed and _row(db, "SELECT id FROM exposure WHERE route_receipt=?", (receipt,)):
            return "already_exposed"
        if route["status"] == "withdrawn":
            return "replayed"
        if route["status"] != "issued":
            return "route_not_withdrawable:" + route["status"]
        db.execute("UPDATE delivered_routes SET status='withdrawn' WHERE receipt=?", (receipt,))
        return "withdrawn"
