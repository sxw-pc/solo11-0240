import json
from .store import one, rows, tx
from . import processing_permit as permits

HOP_KINDS={"queue","cache","forward","accelerator","fallback"}
HOP_CONTENT={"ciphertext","plaintext"}
DUMP_CLASSES={"plaintext","ciphertext","unknown"}

def effective_class(db, dump_row):
    late=one(db,"SELECT content_class FROM dump_class WHERE dump_id=? "
               "ORDER BY at DESC,id DESC LIMIT 1",(dump_row["id"],))
    return late["content_class"] if late else dump_row["content_class"]

def evaluate(db, request_id):
    request=one(db,"SELECT * FROM request WHERE id=?",(request_id,))
    if not request:
        return None
    permit=permits.get(db,request["permit_id"])
    zones=permit["zones"]
    breaches=[]
    pendings=[]
    releases=rows(db,"SELECT * FROM key_release WHERE request_id=? ORDER BY id",(request_id,))
    attestations=rows(db,"SELECT * FROM attestation WHERE request_id=? ORDER BY id",(request_id,))
    hops=rows(db,"SELECT * FROM hop WHERE request_id=? ORDER BY id",(request_id,))
    dumps=rows(db,"SELECT * FROM dump WHERE request_id=? ORDER BY id",(request_id,))
    for release in releases:
        related=[a for a in attestations if a["release_id"]==release["id"]]
        if not related:
            pendings.append("attestation:"+release["id"])
        for att in related:
            detail=dict(device=att["device"],release=release["id"],input=att["input_commitment"])
            if att["at"]<release["at"]:
                breaches.append(("use_before_release",att["zone"],att["at"],att["id"],detail))
            if att["device"]!=release["device"]:
                breaches.append(("key_misuse",att["zone"],att["at"],att["id"],
                                 dict(detail,bound_device=release["device"])))
            if att["zone"] not in zones:
                breaches.append(("compute_outside_permit",att["zone"],att["at"],att["id"],detail))
            if att["input_commitment"]!=request["input_commitment"]:
                breaches.append(("input_mismatch",att["zone"],att["at"],att["id"],
                                 dict(detail,expected=request["input_commitment"])))
            if not permits.valid_at(permit,att["at"]):
                breaches.append(("compute_without_permit",att["zone"],att["at"],att["id"],detail))
            current=permits.version_at(db,permit["id"],att["at"])
            if current is not None and att["permit_version"]!=current:
                breaches.append(("stale_permit_version",att["zone"],att["at"],att["id"],
                                 dict(detail,credential_version=att["permit_version"],
                                      permit_version=current)))
    for hop in hops:
        if hop["content"]=="plaintext" and hop["zone"] not in zones:
            breaches.append(("plaintext_reach",hop["zone"],hop["at"],hop["id"],
                             dict(kind=hop["kind"],principal=hop["principal"],
                                  input=request["input_commitment"])))
    for dump in dumps:
        cls=effective_class(db,dump)
        if cls=="unknown":
            pendings.append("classification:"+dump["id"])
            continue
        if cls=="plaintext":
            for move in rows(db,"SELECT * FROM dump_transfer WHERE dump_id=? "
                                "ORDER BY at,id",(dump["id"],)):
                detail=dict(dump=dump["id"],principal=move["principal"],
                            input=request["input_commitment"])
                if move["to_zone"] not in zones:
                    breaches.append(("plaintext_dump_exposure",move["to_zone"],move["at"],
                                     move["id"],detail))
                elif not permits.authorized(db,permit["id"],request["purpose"],
                                            move["principal"],move["at"]):
                    breaches.append(("unauthorized_plaintext_access",move["to_zone"],move["at"],
                                     move["id"],detail))
    delivery=one(db,"SELECT * FROM delivery WHERE request_id=?",(request_id,))
    if delivery:
        for att in attestations:
            if att["recipient"]!=delivery["recipient"]:
                breaches.append(("output_recipient_mismatch",att["zone"],att["at"],att["id"],
                                 dict(device=att["device"],recipient=att["recipient"],
                                      delivered_to=delivery["recipient"],
                                      input=request["input_commitment"])))
        if attestations and not any(att["output_commitment"]==delivery["output_commitment"]
                                    for att in attestations):
            breaches.append(("output_mismatch","",delivery["at"],delivery["id"],
                             dict(delivered=delivery["output_commitment"],
                                  input=request["input_commitment"])))
    if not releases:
        pendings.append("key_release")
    noticed=one(db,"SELECT id FROM violation WHERE request_id=? LIMIT 1",(request_id,))
    if breaches or noticed:
        compliance="violation"
    elif pendings:
        compliance="pending"
    else:
        compliance="compliant"
    for kind,zone,at,evidence,detail in breaches:
        db.execute("INSERT OR IGNORE INTO violation VALUES(?,?,?,?,?,?,?)",
                   ("v-%s-%s-%s"%(request_id,kind,evidence),request_id,kind,zone,
                    json.dumps(detail,sort_keys=True),at,evidence))
    db.execute("UPDATE request SET compliance=? WHERE id=?",(compliance,request_id))
    if delivery:
        db.execute("UPDATE delivery SET compliance=? WHERE id=?",(compliance,delivery["id"]))
        proof=one(db,"SELECT * FROM delivery_proof WHERE request_id=?",(request_id,))
        if compliance=="compliant" and not proof:
            plaintext_zones=sorted({att["zone"] for att in attestations}
                                   |{hop["zone"] for hop in hops if hop["content"]=="plaintext"}
                                   |{dump["zone"] for dump in dumps
                                     if effective_class(db,dump)=="plaintext"})
            method="ciphertext_assist" if any(hop["zone"] not in zones for hop in hops) else "in_zone"
            db.execute("INSERT INTO delivery_proof VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       ("proof-"+request_id,request_id,permit["id"],
                        permits.version_at(db,permit["id"],delivery["at"]),
                        request["input_commitment"],delivery["output_commitment"],
                        json.dumps([release["id"] for release in releases]),
                        json.dumps(sorted({att["device"] for att in attestations})),
                        json.dumps(plaintext_zones),delivery["at"],method,"issued"))
        elif compliance=="violation" and proof and proof["status"]=="issued":
            db.execute("UPDATE delivery_proof SET status='superseded' WHERE id=?",(proof["id"],))
    return compliance

def receive(db, request_id, permit_id, plan_id, input_commitment, category, purpose, at,
            entry_zone, entry_kind="cache"):
    with tx(db):
        old=one(db,"SELECT * FROM request WHERE id=?",(request_id,))
        if old:
            same=(old["permit_id"],old["plan_id"],old["input_commitment"],old["category"],
                  old["purpose"])==(permit_id,plan_id,input_commitment,category,purpose)
            return "already_accepted" if same else "request_identity_conflict"
        if entry_kind not in HOP_KINDS:
            return "invalid_kind"
        permit=permits.get(db,permit_id)
        if not permit:
            return "unknown_permit"
        plan=one(db,"SELECT * FROM plan WHERE id=?",(plan_id,))
        if not plan or plan["status"] not in ("locked","passed"):
            return "plan_not_active"
        if not plan["start_ts"]<=at<=plan["end_ts"]:
            return "outside_release_window"
        if not permits.valid_at(permit,at):
            return "permit_not_valid"
        if category not in permit["categories"]:
            return "category_not_permitted"
        if purpose not in permit["purposes"]:
            return "purpose_not_permitted"
        db.execute("INSERT INTO request VALUES(?,?,?,?,?,?,?,?,?)",
                   (request_id,permit_id,plan_id,input_commitment,category,purpose,at,
                    "accepted","pending"))
        db.execute("INSERT INTO hop VALUES(?,?,?,?,?,?,?,?)",
                   ("hop-%s-entry"%request_id,request_id,entry_kind,entry_zone,"ciphertext",
                    at,None,None))
        evaluate(db,request_id)
        return "accepted"

def hop(db, hop_id, request_id, kind, zone, at, content="ciphertext", principal=None, ref=None):
    with tx(db):
        if one(db,"SELECT id FROM hop WHERE id=?",(hop_id,)):
            return "duplicate"
        request=one(db,"SELECT * FROM request WHERE id=?",(request_id,))
        if not request:
            return "unknown_request"
        if kind not in HOP_KINDS:
            return "invalid_kind"
        if content not in HOP_CONTENT:
            return "invalid_content"
        if kind=="fallback":
            case=one(db,"SELECT * FROM recovery WHERE id=?",(ref,)) if ref else None
            if not case:
                return "unknown_recovery_case"
            stage=one(db,"SELECT plan_id FROM stage WHERE id=?",(case["stage_id"],))
            plan=one(db,"SELECT service FROM plan WHERE id=?",(stage["plan_id"],))
            serving=one(db,"SELECT service FROM plan WHERE id=?",(request["plan_id"],))
            if plan["service"]!=serving["service"]:
                return "recovery_case_service_mismatch"
        db.execute("INSERT INTO hop VALUES(?,?,?,?,?,?,?,?)",
                   (hop_id,request_id,kind,zone,content,at,principal,ref))
        evaluate(db,request_id)
        return "recorded"

def key_release(db, release_id, request_id, zone, device, at, permit_version):
    with tx(db):
        if one(db,"SELECT id FROM key_release WHERE id=?",(release_id,)):
            return "duplicate"
        request=one(db,"SELECT * FROM request WHERE id=?",(request_id,))
        if not request:
            return "unknown_request"
        if request["status"]=="halted":
            return "request_halted"
        permit=permits.get(db,request["permit_id"])
        if not permits.valid_at(permit,at):
            return "permit_not_valid"
        if zone not in permit["zones"]:
            return "zone_not_permitted"
        current=permits.version_at(db,permit["id"],at)
        if current is None or permit_version!=current:
            return "stale_permit_version"
        db.execute("INSERT INTO key_release VALUES(?,?,?,?,?,?)",
                   (release_id,request_id,zone,device,at,permit_version))
        evaluate(db,request_id)
        return "released"

def attest(db, attestation_id, request_id, release_id, device, zone, at, input_commitment,
           output_commitment, recipient, permit_version):
    with tx(db):
        if one(db,"SELECT id FROM attestation WHERE id=?",(attestation_id,)):
            return "duplicate"
        release=one(db,"SELECT * FROM key_release WHERE id=?",(release_id,))
        if not release or release["request_id"]!=request_id:
            return "unknown_key_release"
        db.execute("INSERT INTO attestation VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (attestation_id,request_id,release_id,device,zone,at,input_commitment,
                    output_commitment,recipient,permit_version))
        evaluate(db,request_id)
        return "recorded"

def derive(db, dump_id, request_id, zone, kind, at, content_class="unknown"):
    with tx(db):
        if one(db,"SELECT id FROM dump WHERE id=?",(dump_id,)):
            return "duplicate"
        if not one(db,"SELECT id FROM request WHERE id=?",(request_id,)):
            return "unknown_request"
        if content_class not in DUMP_CLASSES:
            return "invalid_content_class"
        db.execute("INSERT INTO dump VALUES(?,?,?,?,?,?)",
                   (dump_id,request_id,zone,kind,content_class,at))
        evaluate(db,request_id)
        return "recorded"

def classify(db, class_id, dump_id, content_class, at):
    with tx(db):
        if one(db,"SELECT id FROM dump_class WHERE id=?",(class_id,)):
            return "duplicate"
        dump=one(db,"SELECT * FROM dump WHERE id=?",(dump_id,))
        if not dump:
            return "unknown_dump"
        if content_class not in ("plaintext","ciphertext"):
            return "invalid_content_class"
        current=effective_class(db,dump)
        if current!="unknown":
            return "already_classified" if current==content_class else "classification_conflict"
        db.execute("INSERT INTO dump_class VALUES(?,?,?,?)",(class_id,dump_id,content_class,at))
        evaluate(db,dump["request_id"])
        return "recorded"

def transfer(db, transfer_id, dump_id, to_zone, principal, at):
    with tx(db):
        if one(db,"SELECT id FROM dump_transfer WHERE id=?",(transfer_id,)):
            return "duplicate"
        dump=one(db,"SELECT * FROM dump WHERE id=?",(dump_id,))
        if not dump:
            return "unknown_dump"
        db.execute("INSERT INTO dump_transfer VALUES(?,?,?,?,?)",
                   (transfer_id,dump_id,to_zone,principal,at))
        evaluate(db,dump["request_id"])
        return "recorded"

def deliver(db, delivery_id, request_id, output_commitment, recipient, at):
    with tx(db):
        request=one(db,"SELECT * FROM request WHERE id=?",(request_id,))
        if not request:
            return "unknown_request"
        old=one(db,"SELECT * FROM delivery WHERE request_id=?",(request_id,))
        if old:
            same=(old["output_commitment"],old["recipient"])==(output_commitment,recipient)
            return "already_delivered" if same else "conflicting_delivery"
        if one(db,"SELECT id FROM delivery WHERE id=?",(delivery_id,)):
            return "duplicate"
        if request["status"]=="halted":
            return "request_halted"
        db.execute("INSERT INTO delivery VALUES(?,?,?,?,?,?)",
                   (delivery_id,request_id,output_commitment,recipient,at,"pending"))
        db.execute("UPDATE request SET status='delivered' WHERE id=?",(request_id,))
        return "delivered:"+evaluate(db,request_id)

def query(db, request_id):
    request=one(db,"SELECT * FROM request WHERE id=?",(request_id,))
    if not request:
        return "unknown_request"
    dumps=[]
    for dump in rows(db,"SELECT * FROM dump WHERE request_id=? ORDER BY id",(request_id,)):
        dump["effective_class"]=effective_class(db,dump)
        dump["transfers"]=rows(db,"SELECT * FROM dump_transfer WHERE dump_id=? ORDER BY at,id",
                               (dump["id"],))
        dumps.append(dump)
    return {"request":request,
            "hops":rows(db,"SELECT * FROM hop WHERE request_id=? ORDER BY at,id",(request_id,)),
            "key_releases":rows(db,"SELECT * FROM key_release WHERE request_id=? ORDER BY id",(request_id,)),
            "attestations":rows(db,"SELECT * FROM attestation WHERE request_id=? ORDER BY id",(request_id,)),
            "dumps":dumps,
            "delivery":one(db,"SELECT * FROM delivery WHERE request_id=?",(request_id,)),
            "proof":one(db,"SELECT * FROM delivery_proof WHERE request_id=?",(request_id,)),
            "violations":rows(db,"SELECT * FROM violation WHERE request_id=? ORDER BY id",(request_id,)),
            "disposals":rows(db,"SELECT * FROM disposal WHERE request_id=? ORDER BY id",(request_id,))}
