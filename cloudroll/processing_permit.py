import json
from .store import one, rows, tx

def _decode(permit):
    permit=dict(permit)
    for field in ("categories","purposes","zones"):
        permit[field]=json.loads(permit[field])
    return permit

def get(db, permit_id):
    row=one(db,"SELECT * FROM permit WHERE id=?",(permit_id,))
    return _decode(row) if row else None

def valid_at(permit, at):
    if not permit["valid_from"]<=at<=permit["valid_until"]:
        return False
    if permit["withdrawn_at"] is not None and at>=permit["withdrawn_at"]:
        return False
    return True

def version_at(db, permit_id, at):
    row=one(db,"SELECT version FROM permit_version WHERE permit_id=? AND effective_at<=? "
              "ORDER BY version DESC LIMIT 1",(permit_id,at))
    return row["version"] if row else None

def authorized(db, permit_id, purpose, principal, at):
    return one(db,"SELECT id FROM support_auth WHERE permit_id=? AND principal=? AND purpose=? "
                  "AND valid_from<=? AND valid_until>=?",(permit_id,principal,purpose,at,at)) is not None

def grant(db, permit_id, customer, categories, purposes, zones, valid_from, valid_until,
          withdrawal, effective_at=None):
    with tx(db):
        if not customer or not withdrawal:
            return "invalid_permit"
        if not all(isinstance(terms,list) and terms for terms in (categories,purposes,zones)):
            return "invalid_permit"
        if valid_from>=valid_until:
            return "invalid_validity"
        old=one(db,"SELECT * FROM permit WHERE id=?",(permit_id,))
        if old and old["status"]=="withdrawn":
            return "permit_withdrawn"
        if old and old["customer"]!=customer:
            return "permit_identity_conflict"
        version=1 if not old else old["version"]+1
        effective=valid_from if effective_at is None else effective_at
        packed=[json.dumps(terms,sort_keys=True) for terms in (categories,purposes,zones)]
        db.execute("INSERT INTO permit_version VALUES(?,?,?,?,?,?,?,?)",
                   (permit_id,version,effective,packed[0],packed[1],packed[2],valid_from,valid_until))
        db.execute("INSERT INTO permit(id,customer,categories,purposes,zones,valid_from,valid_until,"
                   "withdrawal,version,status,withdrawn_at) VALUES(?,?,?,?,?,?,?,?,?,'active',NULL) "
                   "ON CONFLICT(id) DO UPDATE SET categories=excluded.categories,"
                   "purposes=excluded.purposes,zones=excluded.zones,valid_from=excluded.valid_from,"
                   "valid_until=excluded.valid_until,withdrawal=excluded.withdrawal,version=excluded.version",
                   (permit_id,customer,packed[0],packed[1],packed[2],valid_from,valid_until,withdrawal,version))
        return "granted" if not old else "amended"

def withdraw(db, permit_id, at):
    with tx(db):
        permit=one(db,"SELECT * FROM permit WHERE id=?",(permit_id,))
        if not permit:
            return "unknown_permit"
        if permit["status"]=="withdrawn":
            return "already_withdrawn"
        db.execute("UPDATE permit SET status='withdrawn',withdrawn_at=? WHERE id=?",(at,permit_id))
        zones=json.loads(permit["zones"])
        for request in rows(db,"SELECT * FROM request WHERE permit_id=?",(permit_id,)):
            if request["status"]!="delivered":
                db.execute("UPDATE request SET status='halted' WHERE id=?",(request["id"],))
            holdings=[(h["id"],h["zone"]) for h in
                      rows(db,"SELECT id,zone FROM hop WHERE request_id=?",(request["id"],))]
            holdings+=[(d["id"],d["zone"]) for d in
                       rows(db,"SELECT id,zone FROM dump WHERE request_id=?",(request["id"],))]
            for holding_id,zone in holdings:
                method="sealed" if zone in zones else "destroyed"
                db.execute("INSERT OR IGNORE INTO disposal VALUES(?,?,?,?,?,?)",
                           ("disp-%s-%s"%(request["id"],holding_id),request["id"],holding_id,
                            zone,method,at))
        return "withdrawn"

def authorize(db, auth_id, permit_id, principal, purpose, valid_from, valid_until):
    with tx(db):
        permit=one(db,"SELECT * FROM permit WHERE id=?",(permit_id,))
        if not permit:
            return "unknown_permit"
        if purpose not in json.loads(permit["purposes"]):
            return "purpose_not_permitted"
        if valid_from>valid_until:
            return "invalid_validity"
        if one(db,"SELECT id FROM support_auth WHERE id=?",(auth_id,)):
            return "duplicate"
        db.execute("INSERT INTO support_auth VALUES(?,?,?,?,?,?)",
                   (auth_id,permit_id,principal,purpose,valid_from,valid_until))
        return "authorized"
