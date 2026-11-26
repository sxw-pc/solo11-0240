"""Cross-device identity challenges and contamination handling.

A shared login session only proves two devices *might* belong to the same
human. Before either device is allowed into the experiment its rendering is
frozen and a version-neutral identity challenge (it never carries an arm or
digest, so answering it cannot leak which version is under test) is issued.

The first challenge may only go out when *every* possible reply still leaves a
feasible four-sample design: the independent branch (the challenged devices
stay separate) must have real usable old/new routes, and the fallback branch
(four operations-approved independent customers) must be feasible as well.
After the reply arrives only the matching branch is executed; the other
branch's candidates are never counted.

If the devices prove to be one person who saw both versions, both original
results are retained but neither is an independent control: the samples are
invalidated with a recorded reason and backups fill the cells. Nothing here
rewrites history — seen content stays seen.
"""
import json

from .store import one, rows, tx

ARMS = ("old", "new")
REGIONS = ("east", "west")
REQUIRED_CELLS = {(arm, region) for arm in ARMS for region in REGIONS}


def get_plan(db, experiment_id):
    row = one(db, "SELECT * FROM experiment_plan WHERE experiment_id=?", (experiment_id,))
    if not row:
        return None
    data = dict(row)
    data["pair_slots"] = json.loads(data["pair_slots"])
    data["unified_slots"] = json.loads(data["unified_slots"])
    data["challenges"] = json.loads(data["challenges"])
    return data


def usable_route(db, device, digest):
    row = one(db, "SELECT status FROM delivered_routes WHERE device=? AND digest=?",
              (device, digest))
    return bool(row) and row["status"] != "withdrawn"


def check_slots(db, slots, digests):
    """Structural and evidence feasibility of one candidate branch."""
    if len(slots) != 4:
        return "invalid_slot_count"
    cells = set()
    seen_devices = set()
    seen_persons = set()
    for slot in slots:
        arm, region, device = slot.get("arm"), slot.get("region"), slot.get("device")
        if arm not in ARMS or region not in REGIONS:
            return "invalid_slot"
        cells.add((arm, region))
        if not device or device in seen_devices:
            return "duplicate_or_missing_device"
        seen_devices.add(device)
        device_row = one(db, "SELECT * FROM device_person WHERE device=?", (device,))
        if not device_row:
            return "unknown_device:" + device
        if device_row["region"] != region:
            return "device_region_mismatch:" + device
        if not usable_route(db, device, digests[arm + "_digest"]):
            return "no_usable_route:" + device
        if device_row["person_id"] in seen_persons:
            return "shared_person_in_branch:" + device
        seen_persons.add(device_row["person_id"])
    if cells != REQUIRED_CELLS:
        return "cells_must_cover_each_arm_in_each_region"
    return "feasible"


def freeze_challenge(db, experiment_id, challenge_id, devices):
    """Freeze rendering and open a version-neutral dual-device challenge."""
    with tx(db):
        if one(db, "SELECT id FROM identity_challenge WHERE id=?", (challenge_id,)):
            prior = one(db, "SELECT status FROM identity_challenge WHERE id=?", (challenge_id,))
            return "replayed:" + prior["status"]
        plan = get_plan(db, experiment_id)
        if not plan:
            return "unknown_experiment"
        if challenge_id not in plan["challenges"]:
            return "challenge_not_authorized"
        if len(devices) != 2 or len(set(devices)) != 2:
            return "invalid_challenge_devices"
        sessions = set()
        for device in devices:
            row = one(db, "SELECT * FROM device_person WHERE device=?", (device,))
            if not row:
                return "unknown_device:" + device
            sessions.add(row["session"])
        if len(sessions) != 1 or None in sessions:
            return "devices_do_not_share_session"
        # Every possible reply must leave a runnable four-sample design.
        digests = {"old_digest": plan["old_digest"], "new_digest": plan["new_digest"]}
        pair_check = check_slots(db, plan["pair_slots"], digests)
        if pair_check != "feasible":
            return "pair_branch_infeasible:" + pair_check
        unified_check = check_slots(db, plan["unified_slots"], digests)
        if unified_check != "feasible":
            return "fallback_branch_infeasible:" + unified_check
        db.execute(
            "INSERT INTO identity_challenge(id,devices,session,status,answer,person_id,reason) "
            "VALUES(?,?,?, 'open',NULL,NULL,NULL)",
            (challenge_id, ",".join(devices), next(iter(sessions))))
        return "frozen"


def _record_contamination(db, experiment_id, person_id, device, digest, arm, reason):
    record_id = "cr:" + experiment_id + ":" + device + ":" + digest
    if not one(db, "SELECT id FROM contamination_record WHERE id=?", (record_id,)):
        db.execute(
            "INSERT INTO contamination_record(id,experiment_id,person_id,device,digest,arm,reason) "
            "VALUES(?,?,?,?,?,?,?)",
            (record_id, experiment_id, person_id, device, digest, arm, reason))


def taint_person(db, experiment_id, person_id, reason):
    """Record every exposure of a merged person and invalidate cross-arm samples."""
    plan = get_plan(db, experiment_id)
    devices = [r["device"] for r in rows(
        db, "SELECT device FROM device_person WHERE person_id=? ORDER BY device", (person_id,))]
    arms_seen = set()
    for device in devices:
        for exposure in rows(db, "SELECT * FROM exposure WHERE device=?", (device,)):
            arm = None
            if exposure["digest"] == plan["new_digest"]:
                arm = "new"
            elif exposure["digest"] == plan["old_digest"]:
                arm = "old"
            if arm is None:
                continue
            arms_seen.add(arm)
            _record_contamination(db, experiment_id, person_id, device, exposure["digest"],
                                  arm, reason)
    if len(arms_seen) == 2:
        # The person has both versions in their history: no sample from them is
        # an independent control. Originals stay on file, flagged not deleted.
        db.execute(
            "UPDATE experiment_sample SET countable=0, reason=? WHERE experiment_id=? "
            "AND person_id=? AND countable=1",
            ("cross_arm_taint:" + reason, experiment_id, person_id))
        return "cross_arm_tainted"
    return "single_arm_recorded"


def resolve_challenge(db, challenge_id, answer, person_id=None):
    """Apply the challenge reply: independent, same person, or no answer."""
    with tx(db):
        challenge = one(db, "SELECT * FROM identity_challenge WHERE id=?", (challenge_id,))
        if not challenge:
            return "unknown_challenge"
        if challenge["status"] != "open":
            if challenge["answer"] == answer:
                return "replayed:" + challenge["status"]
            return "challenge_already_answered"
        if answer not in ("independent", "same", "no_answer"):
            return "invalid_answer"
        devices = challenge["devices"].split(",")
        # The challenges column stores a JSON array; locate the owning plan.
        experiment = None
        for plan_row in rows(db, "SELECT experiment_id FROM experiment_plan"):
            plan = get_plan(db, plan_row["experiment_id"])
            if challenge_id in plan["challenges"]:
                experiment = plan_row["experiment_id"]
                break
        if answer == "independent":
            db.execute(
                "UPDATE identity_challenge SET status='answered', answer='independent', "
                "reason='distinct_customers' WHERE id=?", (challenge_id,))
            return "independent"
        if answer == "no_answer":
            # Identity stays unknown; both devices remain outside the experiment.
            db.execute(
                "UPDATE identity_challenge SET status='no_answer', answer='no_answer', "
                "reason='no_response_devices_excluded' WHERE id=?", (challenge_id,))
            return "no_answer"
        merged_id = person_id or "person:" + min(devices)
        for device in devices:
            row = one(db, "SELECT person_id FROM device_person WHERE device=?", (device,))
            if row["person_id"] != merged_id:
                db.execute("DELETE FROM person_registry WHERE person_id=?", (row["person_id"],))
            db.execute("UPDATE device_person SET person_id=? WHERE device=?",
                       (merged_id, device))
        if not one(db, "SELECT person_id FROM person_registry WHERE person_id=?", (merged_id,)):
            db.execute(
                "INSERT INTO person_registry(person_id,kind,declared,note) VALUES(?,?,?,?)",
                (merged_id, "merged", ",".join(sorted(devices)), "identity_challenge:" + challenge_id))
        db.execute(
            "UPDATE identity_challenge SET status='answered', answer='same', person_id=?, "
            "reason='same_human_dual_device' WHERE id=?", (merged_id, challenge_id))
        if experiment:
            taint = taint_person(db, experiment, merged_id, "same_human_dual_device")
        else:
            taint = "no_experiment"
        return "same:" + taint
