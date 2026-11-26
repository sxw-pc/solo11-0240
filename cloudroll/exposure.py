"""Real exposure receipts and the device/person registry.

A *render receipt* binds together the physical device key, the login session,
the digest of the bytes actually displayed, the render minute and a client
confirmation. Only a confirmed render creates an :class:`exposure` row.

Not every client event is an exposure:

* ``prefetch`` only fetched bytes into the cache; it is recorded as a raw event
  but never creates an exposure, even if the bytes were later displayed.
* retries and same-page re-scans of bytes the device already displayed are
  duplicate signals of the same exposure, not a second one. Exposure identity
  is ``(device, digest)``.

Once an exposure exists it is immutable evidence: a power loss or a receipt
arriving late cannot turn seen content into unseen content. The exposure row
keeps the digest of the bytes as actually displayed, independent of any later
relabelling of routes or samples. A render of bytes whose route was withdrawn
is still accepted as fact (the cache had the bytes); contamination is handled
by the trial layer, not by erasing evidence.
"""
from .store import one, rows, tx

RENDER_KINDS = ("render", "retry", "rescan")


def register_device(db, device, account, region, session=None):
    """Bind a physical device key to an account, region and login session."""
    with tx(db):
        old = one(db, "SELECT * FROM device_person WHERE device=?", (device,))
        if old:
            if (old["account"], old["region"], old["session"]) != (account, region, session):
                raise ValueError("device_identity_conflict")
            return "replayed"
        # A device initially stands alone as its own candidate person until an
        # identity challenge proves it shares a person with another device.
        person_id = "person:" + device
        db.execute(
            "INSERT INTO device_person(device,account,region,session,person_id) VALUES(?,?,?,?,?)",
            (device, account, region, session, person_id))
        db.execute(
            "INSERT INTO person_registry(person_id,kind,declared,note) VALUES(?,?,?,?)",
            (person_id, "independent", device, None))
        return "registered"


def declare_person(db, person_id, devices, note=None):
    """Operations declaration that distinct devices belong to distinct customers."""
    with tx(db):
        if one(db, "SELECT person_id FROM person_registry WHERE person_id=?", (person_id,)):
            existing = rows(db, "SELECT device FROM device_person WHERE person_id=? ORDER BY device",
                            (person_id,))
            if [r["device"] for r in existing] != sorted(devices):
                raise ValueError("person_declaration_conflict")
            return "replayed"
        for device in devices:
            row = one(db, "SELECT * FROM device_person WHERE device=?", (device,))
            if not row:
                return "unknown_device"
            if row["person_id"] != "person:" + device:
                return "device_already_merged:" + device
        for device in devices:
            db.execute("UPDATE device_person SET person_id=? WHERE device=?", (person_id, device))
            db.execute("DELETE FROM person_registry WHERE person_id=?", ("person:" + device,))
        db.execute(
            "INSERT INTO person_registry(person_id,kind,declared,note) VALUES(?,?,?,?)",
            (person_id, "independent", ",".join(sorted(devices)), note))
        return "declared"


def _frozen_by_open_challenge(db, device):
    return one(
        db,
        "SELECT id FROM identity_challenge WHERE status='open' AND ','||devices||',' LIKE ?",
        ("%," + device + ",%",))


def _validated_render(db, device, route_receipt, session, digest):
    device_row = one(db, "SELECT * FROM device_person WHERE device=?", (device,))
    if not device_row:
        return "unknown_device"
    route = one(db, "SELECT * FROM delivered_routes WHERE receipt=?", (route_receipt,))
    if not route:
        return "unknown_route_receipt"
    if route["device"] != device:
        return "route_device_mismatch"
    if route["digest"] != digest:
        return "digest_route_mismatch"
    if session != route["session"]:
        return "session_mismatch"
    frozen = 1 if _frozen_by_open_challenge(db, device) else 0
    return device_row, route, frozen


def report_render_event(db, event_id, device, route_receipt, session, digest, kind,
                        render_minute=None, client_confirmation=None):
    """Accept a raw client signal. Prefetch never counts as an exposure."""
    with tx(db):
        prior = one(db, "SELECT kind FROM client_render_events WHERE id=?", (event_id,))
        if prior:
            return "replayed:" + prior["kind"]
        if kind not in RENDER_KINDS + ("prefetch",):
            return "unknown_event_kind"
        checked = _validated_render(db, device, route_receipt, session, digest)
        if isinstance(checked, str):
            return checked
        if kind == "prefetch":
            db.execute(
                "INSERT INTO client_render_events(id,device,route_receipt,session,digest,kind,"
                "render_minute,client_confirmation,client_confirmed) VALUES(?,?,?,?,?,?,?,?,0)",
                (event_id, device, route_receipt, session, digest, "prefetch", render_minute,
                 client_confirmation))
            return "prefetch_ignored"
        if not client_confirmation:
            return "missing_client_confirmation"
        db.execute(
            "INSERT INTO client_render_events(id,device,route_receipt,session,digest,kind,"
            "render_minute,client_confirmation,client_confirmed) VALUES(?,?,?,?,?,?,?,?,1)",
            (event_id, device, route_receipt, session, digest, kind, render_minute,
             client_confirmation))
        existing = one(db, "SELECT * FROM exposure WHERE device=? AND digest=?", (device, digest))
        if existing:
            # Retry / rescan / power-loss replay of the same displayed bytes:
            # the first display remains the single exposure.
            return "already_exposed:" + existing["id"]
        return _create_exposure(db, "rr:" + event_id, device, route_receipt, session, digest,
                                render_minute, client_confirmation, checked[2])


def render_receipt(db, receipt_id, device, route_receipt, session, digest, render_minute,
                   client_confirmation):
    """Submit a confirmed browser render receipt and, if new, the exposure."""
    with tx(db):
        old = one(db, "SELECT * FROM render_receipts WHERE id=?", (receipt_id,))
        if old:
            if (old["device"], old["route_receipt"], old["session"], old["digest"],
                    old["render_minute"], old["client_confirmation"]) != (
                    device, route_receipt, session, digest, render_minute, client_confirmation):
                raise ValueError("render_receipt_conflict")
            return "replayed"
        if not client_confirmation:
            return "missing_client_confirmation"
        checked = _validated_render(db, device, route_receipt, session, digest)
        if isinstance(checked, str):
            return checked
        existing = one(db, "SELECT * FROM exposure WHERE device=? AND digest=?", (device, digest))
        if existing:
            # A duplicate receipt for already displayed bytes corroborates the
            # exposure but must not create a second one.
            db.execute(
                "INSERT INTO render_receipts(id,device,route_receipt,session,digest,render_minute,"
                "client_confirmation,frozen_at_render,exposure_id) VALUES(?,?,?,?,?,?,?,?,?)",
                (receipt_id, device, route_receipt, session, digest, render_minute,
                 client_confirmation, checked[2], existing["id"]))
            return "duplicate_exposure:" + existing["id"]
        return _create_exposure(db, receipt_id, device, route_receipt, session, digest,
                                render_minute, client_confirmation, checked[2])


def _create_exposure(db, receipt_id, device, route_receipt, session, digest, render_minute,
                     client_confirmation, frozen):
    exposure_id = "exp:" + device + ":" + digest
    db.execute(
        "INSERT INTO render_receipts(id,device,route_receipt,session,digest,render_minute,"
        "client_confirmation,frozen_at_render,exposure_id) VALUES(?,?,?,?,?,?,?,?,?)",
        (receipt_id, device, route_receipt, session, digest, render_minute,
         client_confirmation, frozen, exposure_id))
    db.execute(
        "INSERT INTO exposure(id,device,digest,route_receipt,render_receipt_id,render_minute,session) "
        "VALUES(?,?,?,?,?,?,?)",
        (exposure_id, device, digest, route_receipt, receipt_id, render_minute, session))
    return "exposed"


def person_of(db, device):
    row = one(db, "SELECT person_id FROM device_person WHERE device=?", (device,))
    return row["person_id"] if row else None
