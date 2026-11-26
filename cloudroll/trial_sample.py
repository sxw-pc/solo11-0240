"""Analytical trial samples grounded in confirmed render evidence.

The legacy :func:`record` only anchors a sample to a route receipt (bytes
sent). Experiment samples use :func:`register` instead: the arm is derived
from the digest the device *actually displayed* on a confirmed render receipt,
and registration is atomic with that evidence. Once a sample exists, changing
the digest later cannot move it between arms — the stored arm is frozen, and
the conflicting digest is rejected.

Samples belong to *resolved persons*, not accounts or devices: one human who
saw both versions contributes two originals but zero independent controls.
An experiment is comparable only with four independent, distinct persons
covering every (arm, region) cell. If contamination cannot be backfilled from
unexposed independent backups the round is reported not comparable rather than
padded to four samples.
"""
import json

from .store import one, rows, tx
from . import exposure
from .identity import get_plan, check_slots, REQUIRED_CELLS, taint_person

_LEGACY_DDL = ("CREATE TABLE IF NOT EXISTS trial_samples (sample TEXT PRIMARY KEY, "
               "receipt TEXT NOT NULL, digest TEXT NOT NULL, outcome INTEGER NOT NULL, "
               "experiment_id TEXT, arm TEXT, countable INTEGER NOT NULL DEFAULT 1)")


def record(db, sample, receipt, outcome):
    """Legacy route-only sample. Route receipts are not exposure evidence."""
    with tx(db):
        db.execute(_LEGACY_DDL)
        route = db.execute("SELECT digest FROM delivered_routes WHERE receipt=?", (receipt,)).fetchone()
        if not route:
            raise ValueError("unknown_route_receipt")
        prior = db.execute("SELECT receipt,digest,outcome FROM trial_samples WHERE sample=?",
                           (sample,)).fetchone()
        if prior:
            if tuple(prior) != (receipt, route[0], outcome):
                raise ValueError("sample_conflict")
            return "replayed"
        db.execute("INSERT INTO trial_samples(sample,receipt,digest,outcome) VALUES(?,?,?,?)",
                   (sample, receipt, route[0], outcome))
        return "recorded"


def plan(db, experiment_id, old_digest, new_digest, pair_slots, unified_slots, challenges):
    """Register the two approved arrangements and pre-verify both branches."""
    with tx(db):
        if one(db, "SELECT experiment_id FROM experiment_plan WHERE experiment_id=?",
               (experiment_id,)):
            return "plan_identity_conflict"
        if old_digest == new_digest:
            return "old_new_digests_must_differ"
        digests = {"old_digest": old_digest, "new_digest": new_digest}
        pair_check = check_slots(db, pair_slots, digests)
        if pair_check != "feasible":
            return "pair_branch_infeasible:" + pair_check
        unified_check = check_slots(db, unified_slots, digests)
        if unified_check != "feasible":
            return "unified_branch_infeasible:" + unified_check
        if not challenges:
            return "challenge_required"
        for challenge_id in challenges:
            if one(db, "SELECT id FROM identity_challenge WHERE id=? AND status!='open'",
                   (challenge_id,)):
                return "challenge_already_settled:" + challenge_id
        db.execute(
            "INSERT INTO experiment_plan(experiment_id,old_digest,new_digest,pair_slots,"
            "unified_slots,challenges,branch) VALUES(?,?,?,?,?,?,NULL)",
            (experiment_id, old_digest, new_digest, json.dumps(pair_slots, sort_keys=True),
             json.dumps(unified_slots, sort_keys=True), json.dumps(challenges, sort_keys=True)))
        return "planned"


def select_branch(db, experiment_id, branch):
    """Commit to one arrangements branch. The other branch never gets counted."""
    with tx(db):
        plan_row = get_plan(db, experiment_id)
        if not plan_row:
            return "unknown_experiment"
        if branch not in ("pair", "unified"):
            return "invalid_branch"
        if plan_row["branch"]:
            return "replayed:" + plan_row["branch"] if plan_row["branch"] == branch \
                else "branch_already_locked:" + plan_row["branch"]
        for challenge_id in plan_row["challenges"]:
            challenge = one(db, "SELECT status,answer FROM identity_challenge WHERE id=?",
                            (challenge_id,))
            if not challenge or challenge["status"] == "open":
                return "challenge_still_open:" + challenge_id
            if branch == "pair" and challenge["answer"] != "independent":
                return "pair_branch_requires_independent_answer"
        db.execute("UPDATE experiment_plan SET branch=? WHERE experiment_id=?",
                   (branch, experiment_id))
        return "branch:" + branch


def _arm_for_digest(plan_row, digest):
    if digest == plan_row["old_digest"]:
        return "old"
    if digest == plan_row["new_digest"]:
        return "new"
    return None


def _ensure_render(db, render):
    """Accept either an existing render receipt id or inline render evidence."""
    if isinstance(render, str):
        row = one(db, "SELECT * FROM render_receipts WHERE id=?", (render,))
        if not row:
            return "unknown_render_receipt"
        return row
    result = exposure.render_receipt(db, **render)
    # "exposed", "replayed" and "duplicate_exposure:..." all leave a usable
    # receipt row; anything else is a business rejection.
    if result not in ("exposed", "replayed") and not str(result).startswith(
            "duplicate_exposure:"):
        return result
    return one(db, "SELECT * FROM render_receipts WHERE id=?", (render["receipt_id"],))


def register(db, experiment_id, sample, person_id, device, outcome, render):
    """Register one experiment sample together with its confirmed render fact."""
    with tx(db):
        plan_row = get_plan(db, experiment_id)
        if not plan_row:
            return "unknown_experiment"
        if not plan_row["branch"]:
            return "branch_not_selected"
        slots = plan_row["pair_slots"] if plan_row["branch"] == "pair" else plan_row["unified_slots"]
        slot = next((s for s in slots if s["device"] == device), None)
        device_row = one(db, "SELECT * FROM device_person WHERE device=?", (device,))
        if not device_row:
            return "unknown_device"
        if device_row["person_id"] != person_id:
            return "person_device_mismatch"
        receipt = _ensure_render(db, render)
        if isinstance(receipt, str):
            return receipt
        if receipt["device"] != device:
            return "render_device_mismatch"
        arm = _arm_for_digest(plan_row, receipt["digest"])
        if arm is None:
            return "digest_not_part_of_experiment"
        # A merged person excluded from the selected branch still has real
        # exposures on file. Their originals are retained as evidence but can
        # never count; the arm is taken from the displayed digest, not a slot.
        tainted_person = one(
            db,
            "SELECT 1 FROM contamination_record WHERE experiment_id=? AND person_id=?",
            (experiment_id, person_id))
        if not slot:
            if not tainted_person:
                return "device_not_in_selected_branch:" + device
        else:
            if device_row["region"] != slot["region"]:
                return "region_mismatch"
            if arm != slot["arm"]:
                # The device actually displayed the other version than the route
                # implied (e.g. cache). Relabelling the sample is not allowed.
                return "rendered_arm_conflicts_with_branch_slot"
        prior = one(db, "SELECT * FROM experiment_sample WHERE experiment_id=? AND sample=?",
                    (experiment_id, sample))
        if prior:
            if (prior["person_id"], prior["device"], prior["arm"],
                    prior["render_receipt_id"], prior["outcome"]) != (
                    person_id, device, arm, receipt["id"], outcome):
                return "sample_identity_conflict"
            return "replayed"
        # Same person already enrolled in the other arm: originals stay, the
        # new row is recorded but never counts as an independent control.
        prior_person = one(
            db,
            "SELECT arm FROM experiment_sample WHERE experiment_id=? AND person_id=? AND countable=1",
            (experiment_id, person_id))
        countable = 1
        reason = None
        if tainted_person or (prior_person and prior_person["arm"] != arm):
            countable = 0
            reason = "cross_arm_taint:same_person_saw_both_versions"
            taint_person(db, experiment_id, person_id, "same_person_saw_both_versions")
        if countable:
            used = one(
                db,
                "SELECT COUNT(*) n FROM experiment_sample WHERE experiment_id=? AND arm=? "
                "AND region=? AND countable=1",
                (experiment_id, arm, slot["region"]))["n"]
            if used:
                return "cell_already_filled:" + arm + ":" + slot["region"]
            total = one(
                db,
                "SELECT COUNT(*) n FROM experiment_sample WHERE experiment_id=? AND countable=1",
                (experiment_id,))["n"]
            if total >= 4:
                return "sample_cap_exceeded"
        region = slot["region"] if slot else device_row["region"]
        db.execute(
            "INSERT INTO experiment_sample(experiment_id,sample,person_id,device,region,arm,"
            "render_receipt_id,outcome,countable,reason) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (experiment_id, sample, person_id, device, region, arm, receipt["id"],
             outcome, countable, reason))
        return "recorded_countable" if countable else "recorded_tainted"


def invalidate(db, experiment_id, sample, reason):
    """Administrative invalidation that keeps the original row on file."""
    with tx(db):
        row = one(db, "SELECT countable FROM experiment_sample WHERE experiment_id=? AND sample=?",
                  (experiment_id, sample))
        if not row:
            return "unknown_sample"
        if not row["countable"]:
            return "replayed"
        db.execute(
            "UPDATE experiment_sample SET countable=0, reason=? WHERE experiment_id=? AND sample=?",
            (reason, experiment_id, sample))
        return "invalidated"


def verdict(db, experiment_id):
    """Decide whether the round supports an old-vs-new effect comparison."""
    with tx(db):
        plan_row = get_plan(db, experiment_id)
        if not plan_row:
            return {"comparable": False, "reason": "unknown_experiment", "countable": []}
        samples = rows(
            db,
            "SELECT * FROM experiment_sample WHERE experiment_id=? ORDER BY sample",
            (experiment_id,))
        countable = [s for s in samples if s["countable"]]
        cells = {(s["arm"], s["region"]) for s in countable}
        persons = {s["person_id"] for s in countable}
        invalid = [{"sample": s["sample"], "reason": s["reason"]}
                   for s in samples if not s["countable"]]
        problems = []
        if len(countable) != len(persons):
            problems.append("countable_samples_share_person")
        if len(countable) > 4:
            problems.append("more_than_four_countable_samples")
        if cells != REQUIRED_CELLS:
            missing = sorted(
                arm + ":" + region for arm, region in REQUIRED_CELLS - cells)
            problems.append("uncovered_cells:" + ",".join(missing))
        return {
            "comparable": not problems,
            "branch": plan_row["branch"],
            "countable": countable,
            "invalidated": invalid,
            "reason": "comparable" if not problems else ";".join(problems),
        }
