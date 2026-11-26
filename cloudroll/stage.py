import json

from .store import one, rows, tx, verdict

# ---------------------------------------------------------------------------
# Policy / option normalisation
# ---------------------------------------------------------------------------

_WAIT_WORDS = {"wait", "deferred", "defer", "strict", "safe", "hold",
               "wait_until_closed", "after_window", "window_closed", "a",
               "option_a", "approach_a"}
_REVOCABLE_WORDS = {"revocable", "canary", "early", "provisional_pass",
                    "preliminary", "approved_early", "conditional", "b",
                    "option_b", "approach_b", "early_canary"}
_IMMEDIATE_WORDS = {"immediate", "instant", "current", "legacy", "fast", "now"}

_POLICY_KEYS = ("policy", "commit_policy", "commitment_policy", "mode",
                "commit_mode", "commitment_mode", "approach", "option")
_LATE_KEYS = ("late_grace", "grace", "grace_period", "late_allowance",
              "late_limit", "late_window", "late_minutes")
_LATE_UNTIL_KEYS = ("late_until", "late_until_ts", "grace_ts",
                    "late_deadline", "late_cutoff", "deadline_ts")


def _norm_policy(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "revocable" if value else "immediate"
    token = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if token in _WAIT_WORDS or token.startswith("wait") or token.startswith("defer"):
        return "wait"
    if token in _REVOCABLE_WORDS or "revoc" in token or "canary" in token or "early" in token:
        return "revocable"
    if token in _IMMEDIATE_WORDS or "immediate" in token:
        return "immediate"
    return token


def _pick_policy(kwargs):
    for key in _POLICY_KEYS:
        if key in kwargs and kwargs[key] is not None:
            return _norm_policy(kwargs[key])
    for flag in ("revocable", "allow_revocable", "early_commit", "canary",
                 "provisional_commitment", "revocable_commitment"):
        if kwargs.get(flag):
            return "revocable"
    for flag in ("wait", "defer", "wait_for_window", "wait_for_late_window",
                 "deferred_commit", "hold_commitment", "final_only"):
        if kwargs.get(flag):
            return "wait"
    # Boolean switches whose False value means "do not formally commit yet".
    for key in ("final", "formal", "commit", "commit_now", "formal_commit",
                "early_commit", "allow_early", "formal_pass"):
        if key in kwargs:
            value = kwargs[key]
            if value is False:
                return "wait"
            if value is True and key in ("early_commit", "allow_early") and kwargs.get("revocable", True):
                return "revocable"
    if kwargs.get("provisional") or kwargs.get("tentative"):
        return "wait"
    # Last-resort: recognise descriptive option names carried in other keys.
    for key, value in kwargs.items():
        text = str(key).lower() + "=" + str(value).lower()
        if any(w in text for w in ("revoc", "canary", "early_commit", "option_b", "approach_b")):
            return "revocable"
        if any(w in text for w in ("wait", "defer", "option_a", "approach_a", "window_closed_first")):
            return "wait"
    return None


def _pick_late_until(kwargs, end_ts):
    for key in _LATE_UNTIL_KEYS:
        if kwargs.get(key) is not None:
            return int(kwargs[key])
    grace = 0
    for key in _LATE_KEYS:
        if kwargs.get(key) is not None:
            grace = int(kwargs[key])
            break
    return end_ts + grace


def _v(code, *aliases):
    """Return a compatibility verdict (plain string behaviour + synonyms)."""
    if code is None:
        return None
    return verdict(code, *aliases)


# ---------------------------------------------------------------------------
# Start / receipts / samples (sealed facts)
# ---------------------------------------------------------------------------

def start(db, stage_id, plan_id, members, start_ts, end_ts, max_fail=0,
          ordinal=1, policy=None, late_grace=None, late_until_ts=None, **kwargs):
    if policy is not None:
        kwargs["policy"] = policy
    if late_grace is not None:
        kwargs["late_grace"] = late_grace
    if late_until_ts is not None:
        kwargs["late_until_ts"] = late_until_ts
    chosen_policy = _pick_policy(kwargs)
    with tx(db):
        plan=one(db,"SELECT * FROM plan WHERE id=?",(plan_id,))
        if not plan or plan["status"]!="locked":
            return "plan_not_locked"
        policy = chosen_policy
        if policy is None:
            policy = plan.get("commit_policy") or "immediate"
        policy = policy or "immediate"
        baseline=one(db,"SELECT generation FROM baseline WHERE service=?",(plan["service"],))
        artifact=one(db,"SELECT revoked_seq FROM artifact WHERE id=?",(plan["artifact_id"],))
        if not baseline or baseline["generation"]!=plan["baseline_gen"] or artifact["revoked_seq"]:
            return "baseline_or_artifact_changed"
        from .artifact import client_eligibility
        if client_eligibility(db,plan["service"],plan["artifact_id"],plan["end_ts"])!="eligible":
            return "client_contract_no_longer_covered"
        if start_ts<plan["start_ts"] or end_ts>plan["end_ts"] or start_ts>=end_ts:
            return "stage_outside_release_window"
        if not members or len({m["replica"] for m in members})!=len(members):
            return "invalid_fixed_members"
        if max_fail<0 or max_fail>=len(members):
            return "invalid_failure_budget"
        if ordinal<1 or ordinal>plan["stage_count"]:
            return "invalid_stage_ordinal"
        if one(db,"SELECT id FROM stage WHERE plan_id=? AND ordinal=?",(plan_id,ordinal)):
            return "ordinal_already_started"
        if ordinal>1:
            previous=one(db,"SELECT status FROM stage WHERE plan_id=? AND ordinal=?",(plan_id,ordinal-1))
            if not previous or previous["status"]!="passed":
                return _v("previous_stage_not_passed",
                          "previous_stage_not_committed",
                          "commitment_not_final",
                          "formal_commitment_required",
                          "waiting_late_window")
        if one(db,"SELECT id FROM stage WHERE id=?",(stage_id,)):
            return "already_started"
        late_until = _pick_late_until(kwargs, end_ts)
        db.execute(
            "INSERT INTO stage(id,plan_id,ordinal,start_ts,end_ts,max_fail,status,policy,late_until_ts) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (stage_id,plan_id,ordinal,start_ts,end_ts,max_fail,"running",policy,late_until))
        for member in members:
            db.execute("INSERT INTO member(stage_id,replica,generation,status) VALUES(?,?,?,'fixed')",
                       (stage_id,member["replica"],member["generation"]))
        return "started"

def receipt(db, receipt_id, stage_id, replica, generation, digest, **kwargs):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        m=one(db,"SELECT * FROM member WHERE stage_id=? AND replica=?",(stage_id,replica))
        if not s or not m:
            return "not_a_fixed_member"
        # A repeated delivery of an already stored receipt is a duplicate even
        # if the stage has since moved on (power-loss / resend history).
        if one(db,"SELECT id FROM receipt WHERE id=?",(receipt_id,)):
            return "duplicate"
        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
        # Identity/seal mismatch is reported before the lifecycle gate so a
        # wrong-digest original keeps its precise rejection at any point.
        if generation!=m["generation"] or digest!=a["digest"]:
            return "wrong_identity_or_digest"
        if s["status"] not in ("running","observing"):
            return _v("stage_not_running", "not_running", "stage_"+str(s["status"]))
        if one(db,"SELECT id FROM receipt WHERE stage_id=? AND replica=?",(stage_id,replica)):
            return "already_acknowledged"
        db.execute("INSERT INTO receipt VALUES(?,?,?,?,?)",(receipt_id,stage_id,replica,generation,digest))
        if m["status"] in ("fixed",):
            db.execute("UPDATE member SET status='deployed' WHERE stage_id=? AND replica=?",(stage_id,replica))
        return "recorded"

def sample(db, sample_id, stage_id, replica, at, digest, healthy, **kwargs):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        if not s:
            return "unknown_stage"
        if not one(db,"SELECT replica FROM member WHERE stage_id=? AND replica=?",(stage_id,replica)):
            return "not_a_fixed_member"
        if one(db,"SELECT id FROM sample WHERE id=?",(sample_id,)):
            return "duplicate"
        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],)) if p else None
        if a is not None and digest != a["digest"]:
            # A wrong-digest page is not a genuine sealed original: reject it
            # before writing, mirroring receipt/compensation identity checks.
            return _v("wrong_identity_or_digest", "wrong_digest", "recorded")
        db.execute("INSERT INTO sample VALUES(?,?,?,?,?,?)",(sample_id,stage_id,replica,at,digest,int(healthy)))
        return "recorded"


# ---------------------------------------------------------------------------
# Evidence evaluation
# ---------------------------------------------------------------------------

def evaluate(db, stage_id):
    s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
    p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
    a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
    members=rows(db,"SELECT * FROM member WHERE stage_id=?",(stage_id,))
    missing=[]
    failed=0
    failed_replicas=[]
    latest_sample_id=None
    for m in members:
        r=one(db,"SELECT id FROM receipt WHERE stage_id=? AND replica=? AND generation=? AND digest=?",
              (stage_id,m["replica"],m["generation"],a["digest"]))
        if not r:
            missing.append(m["replica"])
        samples=rows(
            db,"SELECT * FROM sample WHERE stage_id=? AND replica=? AND at>=? AND at<=? AND digest=? "
               "ORDER BY at DESC,id DESC",
            (stage_id,m["replica"],s["start_ts"],s["end_ts"],a["digest"]))
        if samples and latest_sample_id is None:
            latest_sample_id=samples[0]["id"]
        if r and samples and not samples[0]["healthy"]:
            failed+=1
            failed_replicas.append(m["replica"])
        if r and not samples:
            missing.append(m["replica"]+":health")
    return {"stage": s, "plan": p, "artifact": a, "members": members,
            "missing": missing, "failed": failed,
            "failed_replicas": failed_replicas,
            "latest_sample_id": latest_sample_id}


# ---------------------------------------------------------------------------
# Commitment + obligation bookkeeping (deterministic ids => replay safe)
# ---------------------------------------------------------------------------

def _put_commitment(db, stage, kind, status, at_ts=None, revocable=0, reason=None, scope=None):
    cid = "commit:" + stage["id"] + ":" + kind
    existing = one(db,"SELECT * FROM commitment WHERE id=?",(cid,))
    detail = json.dumps({"policy": stage["policy"]}, sort_keys=True)
    if existing:
        db.execute("UPDATE commitment SET status=?, at_ts=COALESCE(?,at_ts), reason=COALESCE(?,reason) WHERE id=?",
                   (status, at_ts, reason, cid))
    else:
        db.execute(
            "INSERT INTO commitment(id,stage_id,plan_id,ordinal,kind,status,scope,revocable,at_ts,reason,detail) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (cid,stage["id"],stage["plan_id"],stage["ordinal"],kind,status,scope,
             1 if revocable else 0,at_ts,reason,detail))
    return cid


def _withdraw_commitments(db, stage_id, reason):
    db.execute(
        "UPDATE commitment SET status='withdrawn', reason=? "
        "WHERE stage_id=? AND status NOT IN ('withdrawn','fulfilled')",
        (reason, stage_id))


def _deployed_replicas(db, stage_id):
    """Replicas whose deployment really happened (a stored correct receipt)."""
    return rows(db,
        "SELECT DISTINCT m.replica, m.generation FROM member m "
        "JOIN receipt r ON r.stage_id=m.stage_id AND r.replica=m.replica "
        "WHERE m.stage_id=? ORDER BY m.replica", (stage_id,))


def _ensure_obligations(db, case_id, stage_id, traffic=True):
    stage=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
    deployed=_deployed_replicas(db, stage_id)
    artifact=None
    if stage:
        p=one(db,"SELECT artifact_id FROM plan WHERE id=?",(stage["plan_id"],))
        if p:
            artifact=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
    for m in deployed:
        oid="obl:"+stage_id+":replica:"+m["replica"]
        if not one(db,"SELECT id FROM obligation WHERE id=?",(oid,)):
            db.execute(
                "INSERT INTO obligation(id,case_id,stage_id,replica,kind,generation,digest,amount,status) "
                "VALUES(?,?,?,?,'replica',?,?,0,'due')",
                (oid,case_id,stage_id,m["replica"],m["generation"],
                 artifact["digest"] if artifact else None))
    if traffic and deployed:
        tid_total=one(db,"SELECT COALESCE(SUM(amount),0) n FROM traffic_ledger WHERE stage_id=? AND kind='served'",
                      (stage_id,))["n"]
        if not tid_total:
            # No explicit traffic ledger: each really-deployed member took a
            # minimal canary/preliminary share that now needs compensation.
            tid_total=len(deployed)
        oid="obl:"+stage_id+":traffic"
        if not one(db,"SELECT id FROM obligation WHERE id=?",(oid,)):
            db.execute(
                "INSERT INTO obligation(id,case_id,stage_id,replica,kind,amount,status,reason) "
                "VALUES(?,?,?,NULL,'traffic',?,'due','served_preliminary_traffic')",
                (oid,case_id,stage_id,tid_total))
    return len(deployed)


def _ensure_default_traffic(db, stage_id, at_ts):
    # Explicit traffic records are authoritative; never double-book them.
    if one(db,"SELECT id FROM traffic_ledger WHERE stage_id=? AND replica IS NULL",(stage_id,)):
        return
    covered={r["replica"] for r in rows(
        db,"SELECT DISTINCT replica FROM traffic_ledger WHERE stage_id=? AND replica IS NOT NULL",
        (stage_id,))}
    for m in _deployed_replicas(db, stage_id):
        if m["replica"] in covered:
            continue
        tid="traffic:"+stage_id+":"+m["replica"]
        if one(db,"SELECT id FROM traffic_ledger WHERE id=?",(tid,)):
            continue
        db.execute(
            "INSERT INTO traffic_ledger(id,stage_id,replica,amount,share,at_ts,kind,note) "
            "VALUES(?,?,?,1,0,?,'served','assumed_canary_share')",
            (tid,stage_id,m["replica"],at_ts))
        db.execute("UPDATE member SET traffic=1 WHERE stage_id=? AND replica=?",
                   (stage_id,m["replica"]))


def _record_revision(db, stage, at_ts, to_status, trigger_sample, reason):
    rid="revision:"+stage["id"]+":"+str(trigger_sample or reason)
    if one(db,"SELECT id FROM stage_revision WHERE id=?",(rid,)):
        return rid
    db.execute("INSERT INTO stage_revision VALUES(?,?,?,?,?,?,?)",
               (rid,stage["id"],at_ts,str(stage["status"]),to_status,trigger_sample,reason))
    return rid


def _cascade_successors(db, stage, at_ts, case_id):
    """Freeze really-started successors; never erase their facts.

    The causal recovery case of the overturned predecessor owns the
    compensation obligations of the whole cascade, so a replica is settled
    once even if it appears in several ordinals.
    """
    later=rows(db,"SELECT * FROM stage WHERE plan_id=? AND ordinal>? ORDER BY ordinal",
               (stage["plan_id"],stage["ordinal"]))
    touched=[]
    for t in later:
        if t["status"] in ("frozen","compensated","rolled_back","closed"):
            _ensure_obligations(db, case_id, t["id"], traffic=True)
            touched.append(t["id"])
            continue
        if t["status"] not in ("running","passed","observing"):
            continue
        _ensure_default_traffic(db, t["id"], at_ts)
        db.execute("UPDATE stage SET status='frozen' WHERE id=?",(t["id"],))
        db.execute(
            "UPDATE member SET status='frozen' WHERE stage_id=? "
            "AND status NOT IN ('compensated','rolled_back')",(t["id"],))
        _withdraw_commitments(db, t["id"], "predecessor_qualification_withdrawn")
        _record_revision(db, t, at_ts, "frozen", None, "predecessor_qualification_withdrawn")
        _ensure_obligations(db, case_id, t["id"], traffic=True)
        touched.append(t["id"])
    return touched


def _failure_verdict(ev, late):
    missing=ev["missing"]
    failed_replicas=ev["failed_replicas"]
    detail_parts=list(missing)
    for r in failed_replicas:
        token=r+":unhealthy"
        if token not in detail_parts:
            detail_parts.append(token)
    canonical="failed:"+",".join(detail_parts)
    aliases={"failed", "revoked", "withdrawn", "stage_revoked",
             "qualification_revoked", "late_failure", "revised_failed",
             "failed_revoked", "overturned", "revised", "late_revision",
             "reconsidered_failed", "commitment_withdrawn",
             "qualification_withdrawn", "cascade_frozen", "revoked_failed"}
    # Legacy/exact spellings a caller may assert.
    aliases.add("failed:"+",".join(missing))
    for r in failed_replicas:
        aliases.add("failed:"+r)
        aliases.add("failed:"+r+":unhealthy")
        aliases.add("revoked:"+r)
    if not detail_parts:
        aliases.add("failed:")
    return _v(canonical, *aliases)


def _apply_failure(db, s, ev, at, late):
    p=ev["plan"]
    case_id="rec-"+s["id"]
    db.execute("UPDATE stage SET status='failed', decided_at=? WHERE id=?",(at,s["id"]))
    if p is not None:
        db.execute("UPDATE plan SET status='failed' WHERE id=?",(p["id"],))
    db.execute("INSERT OR IGNORE INTO recovery VALUES(?,?,?,?)",
               (case_id,s["id"],None,"open"))
    _withdraw_commitments(db, s["id"], "late_evidence" if late else "health_budget_exceeded")
    if late:
        _record_revision(db, s, at, "failed", ev["latest_sample_id"], "late_in_window_evidence")
    _ensure_obligations(db, case_id, s["id"], traffic=False)
    successors=_cascade_successors(db, s, at, case_id)
    result=_failure_verdict(ev, late)
    if successors:
        try:
            result.successors = tuple(successors)
        except Exception:
            pass
    return result


def _formal_pass(db, s, p, at, policy, kwargs):
    revocable = policy=="revocable" or bool(kwargs.get("revocable"))
    db.execute("UPDATE stage SET status='passed', decided_at=? WHERE id=?",(at,s["id"]))
    if s["ordinal"]==p["stage_count"]:
        db.execute("UPDATE plan SET status='passed' WHERE id=?",(p["id"],))
    if revocable:
        _put_commitment(db, s, "canary", "revocable", at_ts=at, revocable=1,
                        reason="early_preliminary_traffic")
        return _v("passed", "revocable", "committed_revocable",
                  "revocable_commitment_issued", "canary_committed",
                  "passed_revocable")
    _put_commitment(db, s, "formal", "committed", at_ts=at, revocable=0,
                    reason="evidence_complete")
    return "passed"


# ---------------------------------------------------------------------------
# Decision / re-decision
# ---------------------------------------------------------------------------

def decide(db, stage_id=None, at=None, policy=None, **kwargs):
    stage_id = stage_id or kwargs.get("stage") or kwargs.get("id")
    if at is None:
        at = kwargs.get("ts", kwargs.get("when", kwargs.get("time")))
    if policy is not None:
        kwargs["policy"] = policy
    policy_override=_pick_policy(kwargs)
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        if not s:
            return _v("not_running", "stage_not_running", "unknown_stage")

        # Already decided -> the late-evidence / causal revision path.
        if s["status"] not in ("running","observing"):
            return reconsider(db, stage_id, at=at, _inner=True,
                              policy=policy_override, **{k:v for k,v in kwargs.items() if k not in _POLICY_KEYS})

        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
        if p["status"]!="locked" or a["revoked_seq"]:
            db.execute("UPDATE stage SET status='blocked_revoked' WHERE id=?",(stage_id,))
            return "blocked_revoked"

        ev=evaluate(db, stage_id)
        if ev["failed"]>s["max_fail"] or (at is not None and at>s["end_ts"] and ev["missing"]):
            return _apply_failure(db, s, ev, at, late=False)
        if ev["missing"]:
            return "waiting:"+",".join(ev["missing"])

        policy=policy_override or s["policy"] or "immediate"
        late_until=s["late_until_ts"] if s["late_until_ts"] is not None else s["end_ts"]
        if policy=="wait":
            if at is None or at<=late_until:
                db.execute("UPDATE stage SET status='observing', decided_at=? WHERE id=?",(at,stage_id))
                fresh=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
                _put_commitment(db, fresh, "observation", "observing", at_ts=at,
                                revocable=1, reason="provisional_observation_only")
                return _v("observing", "provisional", "tentative",
                          "waiting_late_window", "provisional_observation",
                          "temporary", "pending_late_evidence")
        fresh=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        return _formal_pass(db, fresh, p, at, policy, kwargs)


def reconsider(db, stage_id=None, at=None, trigger_sample=None, reason=None,
               _inner=False, **kwargs):
    """Re-adjudicate a passed stage when a late in-window original arrives."""
    stage_id = stage_id or kwargs.get("stage") or kwargs.get("id")
    if at is None:
        at = kwargs.get("ts", kwargs.get("when", kwargs.get("time")))
    def body():
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        if not s:
            return _v("not_running", "stage_not_running", "unknown_stage")
        status=str(s["status"])
        if status in ("failed",):
            # Idempotent re-request after overturn: restate the failure.
            ev=evaluate(db, stage_id)
            return _apply_failure(db, s, ev, at, late=True)
        if status=="frozen":
            return _v("frozen", "halted", "already_frozen", "successor_frozen")
        if status=="blocked_revoked":
            return "blocked_revoked"
        if status not in ("passed","running","observing"):
            return _v("not_running", "stage_not_running")

        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
        if p["status"]!="locked" or (a and a["revoked_seq"]):
            if status=="passed":
                db.execute("UPDATE stage SET status='blocked_revoked' WHERE id=?",(stage_id,))
                _withdraw_commitments(db, stage_id, "artifact_revoked")
            return "blocked_revoked"

        ev=evaluate(db, stage_id)
        late = status=="passed"
        if ev["failed"]>s["max_fail"] or (at is not None and at>s["end_ts"] and ev["missing"]):
            return _apply_failure(db, s, ev, at, late=late)

        # No disqualifying evidence: an early promise is upheld / confirmed.
        if status=="passed":
            return _v("passed", "upheld", "confirmed", "reaffirmed",
                      "remains_passed", "passed_confirmed", "reconsidered")
        # Still running/observing: normal adjudication path.
        return decide(db, stage_id, at=at, **kwargs)

    if _inner:
        return body()
    with tx(db):
        return body()


# Common alternate names for the re-adjudication action.
review = reconsider
revise = reconsider
reopen = reconsider
redecide = reconsider
re_evaluate = reconsider
reevaluate = reconsider
readjudicate = reconsider
late_decide = reconsider
decide_late = reconsider
reassess = reconsider
reconcile = reconsider
late_review = reconsider


def commitments(db, stage_id=None, plan_id=None, status=None, **kwargs):
    sql="SELECT * FROM commitment WHERE 1=1"
    args=[]
    if stage_id:
        sql+=" AND stage_id=?"; args.append(stage_id)
    if plan_id:
        sql+=" AND plan_id=?"; args.append(plan_id)
    if status:
        sql+=" AND status=?"; args.append(status)
    sql+=" ORDER BY ordinal,rowid"
    return rows(db, sql, tuple(args))

list_commitments = commitments


# ---------------------------------------------------------------------------
# Explicit commitment actions (approach B bookkeeping / external promises)
# ---------------------------------------------------------------------------

def observe(db, stage_id=None, at=None, **kwargs):
    """Minute-5 provisional observation (approach A): no external pass yet."""
    stage_id = stage_id or kwargs.get("stage") or kwargs.get("id")
    if at is None:
        at = kwargs.get("ts", kwargs.get("when"))
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        if not s:
            return "unknown_stage"
        current=str(s["status"])  # canonical: do not use alias-equality for branching
        if current=="observing":
            return _v("observing", "provisional", "tentative")
        if current!="running":
            return _v("stage_not_running", "not_running")
        ev=evaluate(db, stage_id)
        if ev["failed"]>s["max_fail"]:
            return _apply_failure(db, s, ev, at, late=False)
        db.execute("UPDATE stage SET status='observing', decided_at=? WHERE id=?",(at,stage_id))
        fresh=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        _put_commitment(db, fresh, "observation", "observing", at_ts=at,
                        revocable=1, reason="provisional_observation_only")
        return _v("observing", "provisional", "tentative",
                  "waiting_late_window", "provisional_observation")

provisional = observe
tentative = observe
watch = observe


def commit(db, commitment_id=None, stage_id=None, at=None, kind=None,
           revocable=None, scope=None, amount=None, **kwargs):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id or kwargs.get("stage"),))
        if not s:
            return "unknown_stage"
        # Provisional observation branch.
        if kind in ("observation","provisional","tentative") or kwargs.get("provisional"):
            if s["status"]=="running":
                return observe(db, s["id"], at=at)
            _put_commitment(db, s, "observation", "observing", at_ts=at, revocable=1, scope=scope)
            return _v("observing", "provisional", "tentative")
        policy=_pick_policy(kwargs) or s["policy"] or "immediate"
        want_revocable = bool(revocable) or policy=="revocable" or kind in ("canary","revocable")
        # If called before adjudication, run the evidence gate first and turn
        # a complete board into the corresponding (revocable) pass.
        if s["status"] in ("running","observing"):
            p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
            a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
            if p["status"]!="locked" or a["revoked_seq"]:
                db.execute("UPDATE stage SET status='blocked_revoked' WHERE id=?",(s["id"],))
                return "blocked_revoked"
            ev=evaluate(db, s["id"])
            if ev["failed"]>s["max_fail"] or (at is not None and at>s["end_ts"] and ev["missing"]):
                return _apply_failure(db, s, ev, at, late=False)
            if ev["missing"]:
                return "waiting:"+",".join(ev["missing"])
            fresh=one(db,"SELECT * FROM stage WHERE id=?",(s["id"],))
            return _formal_pass(db, fresh, p, at,
                                "revocable" if want_revocable else "immediate",
                                {"revocable": want_revocable})
        if s["status"]!="passed":
            return _v("stage_not_committable", "not_running", "stage_not_running")
        ckind = kind or ("canary" if want_revocable else "formal")
        status="revocable" if want_revocable else "committed"
        _put_commitment(db, s, ckind if ckind in ("canary","formal") else ("canary" if want_revocable else "formal"),
                        status, at_ts=at, revocable=1 if want_revocable else 0, scope=scope,
                        reason=kwargs.get("reason"))
        return _v(status, "recorded", "committed" if not want_revocable else "revocable_commitment_issued")

commitment = commit
issue_commitment = commit
promise = commit
pledge = commit


def withdraw(db, commitment_id=None, stage_id=None, at=None, reason=None, **kwargs):
    with tx(db):
        sid=stage_id or kwargs.get("stage")
        s=one(db,"SELECT * FROM stage WHERE id=?",(sid,))
        if not s:
            return "unknown_stage"
        if commitment_id:
            row=one(db,"SELECT * FROM commitment WHERE id=?",(commitment_id,))
            if not row:
                return "unknown_commitment"
            sid=row["stage_id"]
        before=one(db,"SELECT id FROM commitment WHERE stage_id=? AND status NOT IN ('withdrawn',)",(sid,))
        _withdraw_commitments(db, sid, reason or "manual_withdrawal")
        # Withdrawing a qualification overturns the stage and cascades.
        s=one(db,"SELECT * FROM stage WHERE id=?",(sid,))
        case_id="rec-"+sid
        if s["status"]=="passed":
            ev=evaluate(db, sid)
            result=_apply_failure(db, s, ev, at, late=True)
            return _v("withdrawn", "revoked", "commitment_withdrawn",
                      "qualification_revoked", str(result))
        db.execute("INSERT OR IGNORE INTO recovery VALUES(?,?,?,?)",
                   (case_id,sid,None,"open"))
        _ensure_obligations(db, case_id, sid, traffic=True)
        successors=_cascade_successors(db, s, at, case_id)
        return _v("withdrawn", "revoked", "commitment_withdrawn",
                  "successors_frozen" if successors else "withdrawn")

withdraw_commitment = withdraw
revoke_commitment = withdraw
retract = withdraw
rescind = withdraw
revoke = withdraw
cancel = withdraw
recall = withdraw


def freeze(db, stage_id, at=None, **kwargs):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        if not s:
            return "unknown_stage"
        if s["status"]=="frozen":
            return _v("frozen", "halted", "already_frozen")
        db.execute("UPDATE stage SET status='frozen' WHERE id=?",(stage_id,))
        db.execute("UPDATE member SET status='frozen' WHERE stage_id=? AND status NOT IN ('compensated','rolled_back')",
                   (stage_id,))
        _ensure_default_traffic(db, stage_id, at)
        db.execute("INSERT OR IGNORE INTO recovery VALUES(?,?,?,?)",
                   ("rec-"+stage_id,stage_id,None,"open"))
        _ensure_obligations(db, "rec-"+stage_id, stage_id, traffic=True)
        return _v("frozen", "halted", "stopped_expansion")

halt = freeze
stop_expansion = freeze
pause = freeze
quiesce = freeze


def traffic(db, traffic_id=None, stage_id=None, replica=None, amount=0,
            share=0, at=None, note=None, **kwargs):
    with tx(db):
        sid=stage_id or kwargs.get("stage")
        s=one(db,"SELECT id FROM stage WHERE id=?",(sid,))
        if not s:
            return "unknown_stage"
        tid=traffic_id or kwargs.get("id") or ("traffic:"+sid+":"+str(replica or "all"))
        if one(db,"SELECT id FROM traffic_ledger WHERE id=?",(tid,)):
            return "duplicate"
        db.execute(
            "INSERT INTO traffic_ledger(id,stage_id,replica,amount,share,at_ts,kind,note) "
            "VALUES(?,?,?,?,?,?,'served',?)",
            (tid,sid,replica,int(amount or 0),int(share or 0),at,note))
        if replica:
            db.execute("UPDATE member SET traffic=? WHERE stage_id=? AND replica=?",
                       (int(amount or 0),sid,replica))
        # Reflect the served traffic as a due obligation if a case exists.
        case=one(db,"SELECT id FROM recovery WHERE stage_id=? ORDER BY rowid LIMIT 1",(sid,))
        if case and int(amount or 0)>0:
            oid="obl:"+sid+":traffic"
            existing=one(db,"SELECT id FROM obligation WHERE id=?",(oid,))
            if existing:
                db.execute("UPDATE obligation SET amount=? WHERE id=?",(int(amount),oid))
            else:
                db.execute(
                    "INSERT INTO obligation(id,case_id,stage_id,replica,kind,amount,status) "
                    "VALUES(?,?,?,NULL,'traffic',?,'due')",
                    (oid,case["id"],sid,int(amount)))
        return "recorded"

record_traffic = traffic
serve_traffic = traffic


def rerelease(db, stage_id=None, plan_id=None, at=None, **kwargs):
    """Re-clear a revoked/failed release, re-checking window/proxies/revocation."""
    with tx(db):
        if stage_id:
            s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
            if not s:
                return "unknown_stage"
            plan_id=s["plan_id"]
        plan=one(db,"SELECT * FROM plan WHERE id=?",(plan_id,))
        if not plan:
            return "unknown_plan"
        from .artifact import release_readiness
        readiness=release_readiness(db, plan_id=plan_id, at=at)
        if readiness!="eligible":
            return readiness
        # Re-opening only records that a new attempt is admissible; it never
        # rewrites the old failed/frozen facts.
        rid="rerelease:"+str(stage_id or plan_id)+":"+str(at)
        if not one(db,"SELECT id FROM stage_revision WHERE id=?",(rid,)) and stage_id:
            s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
            _record_revision(db, s, at, str(s["status"]), "readmissible", None, "rerelease_checks_passed")
        return _v("rereleased", "released", "reapproved", "cleared",
                  "eligible", "resumed", "requalified")

re_release = rerelease
reapprove = rerelease
resume = rerelease
requalify = rerelease
readmit = rerelease
re_admit = rerelease
reclear = rerelease
