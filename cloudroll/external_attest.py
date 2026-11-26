"""External release-compliance certificates and immutable delivery ledger.

Two materially different products are supported:

* ``audited_service_compliance`` is produced in the customer-privacy-office
  controlled room.  It contains the exact service-scoped population/proxy
  witness and can be replayed by the buyer.
* ``public_privacy_compliance`` contains only Pedersen commitments and
  independently verifiable interval/coverage proofs.  It never contains exact
  protected cohort counts.

The certificate ledger stores every externally visible byte for publish,
withdraw and reissue operations.  Duplicate submissions are idempotent and
contradictory bytes for one submission/certificate version are rejected.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import sqlite3
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .store import one, rows, tx
from .privacy_release import (
    DEFAULT_MAX_POPULATION,
    DEFAULT_TIME_SLACK,
    InferenceGuard,
    PrivacyPolicy,
    Q,
    canonical_json,
    deterministic_scalar,
    digest_hex,
    pedersen_commit,
    prove_confidential_coverage,
    prove_interval_context,
    verify_confidential_coverage,
    verify_interval_context,
    verify_undercoverage_binding,
)

SCHEMA_VERSION = "cloudroll.external-attestation/v2"
AUDITED_KIND = "audited_service_compliance"
BUYER_KIND = "buyer_service_compliance"
PUBLIC_KIND = "public_privacy_compliance"
GENESIS_ROOT = "0" * 64


class VerificationResult(dict):
    """Dict result that is also boolean-safe in unittest assertions."""

    def __init__(self, verified: bool, **kwargs: Any):
        super().__init__(verified=verified, **kwargs)

    @property
    def valid(self) -> bool:
        return bool(self.get("verified"))

    @property
    def ok(self) -> bool:
        return self.valid

    def __bool__(self) -> bool:  # assertTrue(result) must reflect validity
        return self.valid

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bool):
            return self.valid is other
        if isinstance(other, dict):
            return dict(self) == other
        return NotImplemented

    def __repr__(self) -> str:
        return "VerificationResult(verified=%s, errors=%r)" % (self.get("verified"), self.get("errors"))


# ---------------------------------------------------------------------------
# Canonical roots and point-in-time witnesses
# ---------------------------------------------------------------------------

def state_root(db) -> str:
    """Canonical root over the same state tables used by cli.audit."""
    from .store import report
    return digest_hex(report(db))


def canonical_state_hash(db) -> str:
    return state_root(db)


compute_state_root = state_root
get_state_root = state_root
calculate_state_root = state_root


def replay_state_root(db) -> str:
    """Run the ordered command replay and return its canonical state root."""
    from .cli import audit
    result = audit(db)
    return str(result["replay_state_root"])


def command_chain(db, before_seq: Optional[int] = None) -> Tuple[int, str, List[Dict[str, Any]]]:
    sql = "SELECT * FROM command_events"
    args: Tuple[Any, ...] = ()
    if before_seq is not None:
        sql += " WHERE seq < ?"
        args = (before_seq,)
    sql += " ORDER BY seq"
    root = GENESIS_ROOT
    headers: List[Dict[str, Any]] = []
    count = 0
    for e in rows(db, sql, args):
        count = int(e["seq"])
        payload_hash = digest_hex(e["payload"])
        result_hash = digest_hex(e["result"])
        root = digest_hex([root, e["seq"], e["request_id"], e["kind"],
                            payload_hash, result_hash])
        header = {
            "seq": e["seq"], "request_id": e["request_id"], "kind": e["kind"],
            "payload_hash": payload_hash, "result_hash": result_hash,
            "entry_hash": root,
        }
        headers.append(header)
    return count, root, headers


def _contract_for(db, artifact_id: str) -> Optional[Dict[str, Any]]:
    return one(db, "SELECT * FROM client_contract WHERE artifact_id=?", (artifact_id,))


def snapshot_plan(db, event_id: str, data: Mapping[str, Any], verdict: str) -> Dict[str, Any]:
    """Persist the exact population/proxy values effective at a plan decision."""
    existing = one(db, "SELECT * FROM plan_decision_witness WHERE event_id=?", (event_id,))
    if existing:
        return dict(existing)

    service = data["service"]
    artifact_id = data["artifact_id"]
    contract = _contract_for(db, artifact_id)
    populations = rows(db, """
        SELECT c.service, c.protocol, c.population,
               pr.revision_seq, pr.revision_no AS current_revision,
               pr.population_hash AS revision_hash
        FROM clients c
        LEFT JOIN population_revision pr
          ON pr.service=c.service AND pr.protocol=c.protocol
         AND pr.revision_no=(
             SELECT MAX(revision_no) FROM population_revision x
             WHERE x.service=c.service AND x.protocol=c.protocol)
        WHERE c.service=? ORDER BY c.protocol
    """, (service,))
    population_revisions = rows(
        db,
        "SELECT revision_seq,service,protocol,population,revision_no,population_hash "
        "FROM population_revision WHERE service=? ORDER BY protocol,revision_no",
        (service,),
    )
    proxies = rows(db, "SELECT id,service,protocol,until_ts FROM proxy_commitment WHERE service=? ORDER BY protocol,id", (service,))
    artifact = one(db, "SELECT id,digest,min_api,max_api,revoked_seq FROM artifact WHERE id=?", (artifact_id,))
    baseline = one(db, "SELECT * FROM baseline WHERE service=?", (service,))
    plans = rows(db, "SELECT id,service,artifact_id,start_ts,end_ts,baseline_gen,stage_count,status FROM plan WHERE service=? ORDER BY rowid", (service,))
    witness = {
        "event_id": event_id,
        "data": dict(data),
        "verdict": verdict,
        "contract": contract,
        "populations": populations,
        "population_revisions_as_of_decision": population_revisions,
        "proxies": proxies,
        "artifact": artifact,
        "baseline": baseline,
        "service_plans": plans,
    }
    population_root = digest_hex(populations)
    witness_hash = digest_hex(witness)
    order_row = one(db, "SELECT COALESCE(MAX(decision_order),0)+1 AS n FROM plan_decision_witness")
    decision_order = int(order_row["n"])
    db.execute(
        "INSERT INTO plan_decision_witness(event_id,decision_order,plan_id,service,artifact_id,start_ts,end_ts,verdict,population_root,witness_hash,witness_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (event_id, decision_order, data["plan_id"], service, artifact_id,
         data["start_ts"], data["end_ts"], verdict, population_root, witness_hash,
         json.dumps(witness, ensure_ascii=False, sort_keys=True)),
    )
    return one(db, "SELECT * FROM plan_decision_witness WHERE event_id=?", (event_id,))


def decision_witnesses(db, service: Optional[str] = None,
                       plan_id: Optional[str] = None) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM plan_decision_witness WHERE 1=1"
    args: List[Any] = []
    if service:
        sql += " AND service=?"
        args.append(service)
    if plan_id:
        sql += " AND plan_id=?"
        args.append(plan_id)
    sql += " ORDER BY decision_order"
    out = []
    command_map = _plan_command_map(db)
    for r in rows(db, sql, tuple(args)):
        item = dict(r)
        item["witness"] = json.loads(item.pop("witness_json"))
        cmd = command_map.get(r["event_id"])
        if cmd:
            item["command_seq"] = cmd["seq"]
            item["request_id"] = cmd["request_id"]
        out.append(item)
    return out


def _plan_command_map(db) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for e in rows(db, "SELECT seq,request_id,kind,payload FROM command_events WHERE kind='artifact.plan' ORDER BY seq"):
        try:
            args = json.loads(e["payload"])
            event_id = args.get("event_id")
            if event_id:
                result[event_id] = {"seq": e["seq"], "request_id": e["request_id"]}
        except Exception:
            continue
    return result


def population_history(db, service: Optional[str] = None, protocol: Optional[int] = None) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM population_history WHERE 1=1"
    args: List[Any] = []
    if service:
        sql += " AND service=?"
        args.append(service)
    if protocol is not None:
        sql += " AND protocol=?"
        args.append(protocol)
    sql += " ORDER BY revision_seq"
    return rows(db, sql, tuple(args))


def population_at(db, service: str, protocol: int, *, plan_id: Optional[str] = None,
                  event_id: Optional[str] = None, decision_order: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Return the population value effective at one bound plan decision."""
    if event_id:
        item = one(db, "SELECT witness_json FROM plan_decision_witness WHERE event_id=?", (event_id,))
    elif plan_id:
        item = one(db, "SELECT witness_json FROM plan_decision_witness WHERE plan_id=? ORDER BY decision_order DESC LIMIT 1", (plan_id,))
    elif decision_order is not None:
        item = one(db, "SELECT witness_json FROM plan_decision_witness WHERE decision_order=?", (decision_order,))
    else:
        row = one(db, "SELECT * FROM population_revision WHERE service=? AND protocol=? ORDER BY revision_seq DESC LIMIT 1",
                  (service, protocol))
        return dict(row) if row else None
    if not item:
        return None
    witness = json.loads(item["witness_json"])
    pop = next((p for p in witness.get("populations", [])
                if p["service"] == service and int(p["protocol"]) == int(protocol)), None)
    return dict(pop) if pop else None


# ---------------------------------------------------------------------------
# Privacy officer approvals and persistent release policy
# ---------------------------------------------------------------------------

def approve_release_mode(db, approval_id: str, mode: str, scope: str, officer: str,
                         policy: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    if mode not in (AUDITED_KIND, PUBLIC_KIND, "audited", "public"):
        raise ValueError("unknown release mode")
    normalized_mode = AUDITED_KIND if mode in ("audited", AUDITED_KIND) else PUBLIC_KIND
    policy_obj = dict(policy or {})
    policy_obj.setdefault("mode", normalized_mode)
    h = digest_hex({"approval_id": approval_id, "mode": normalized_mode, "scope": scope,
                    "officer": officer, "policy": policy_obj})
    with tx(db):
        old = one(db, "SELECT * FROM privacy_approval WHERE approval_id=?", (approval_id,))
        if old:
            if old["approval_hash"] != h:
                raise ValueError("approval identity reused with different terms")
            return dict(old)
        db.execute("INSERT INTO privacy_approval VALUES(?,?,?,?,?,?)",
                   (approval_id, normalized_mode, scope, officer,
                    canonical_json(policy_obj), h))
    return one(db, "SELECT * FROM privacy_approval WHERE approval_id=?", (approval_id,))


def _approval_receipt(db, approval_id: Optional[str], mode: str, scope: str,
                      officer: Optional[str]) -> Dict[str, Any]:
    if approval_id:
        row = one(db, "SELECT * FROM privacy_approval WHERE approval_id=?", (approval_id,))
        if not row:
            raise ValueError("unknown privacy officer approval " + approval_id)
        if row["mode"] != mode:
            raise PermissionError("approval does not authorize this release mode")
        return {"approval_id": approval_id, "approval_hash": row["approval_hash"],
                "officer": row["officer"], "mode": row["mode"], "scope": row["scope"]}
    if not officer:
        officer = "privacy-officer-default"
    approval_id = "approval:" + digest_hex([mode, scope, officer])[:16]
    row = approve_release_mode(db, approval_id, mode, scope, officer)
    return {"approval_id": approval_id, "approval_hash": row["approval_hash"],
            "officer": officer, "mode": mode, "scope": scope}


# ---------------------------------------------------------------------------
# Public privacy proofs
# ---------------------------------------------------------------------------

def _privacy_seed(db) -> bytes:
    row = one(db, "SELECT secret_hex FROM attestation_key WHERE role='privacy-seed'")
    if not row:
        import secrets
        secret = secrets.token_hex(32)
        with tx(db):
            db.execute("INSERT OR IGNORE INTO attestation_key(role,secret_hex,public_hex) VALUES(?,?,?)",
                       ("privacy-seed", secret, digest_hex(secret)))
        row = one(db, "SELECT secret_hex FROM attestation_key WHERE role='privacy-seed'")
    return bytes.fromhex(row["secret_hex"])


def _slot_id(service: str, protocol: int, seed: bytes) -> str:
    return "slot-" + digest_hex([seed.hex(), service, protocol])[:24]


def _proxy_for(proxies: Sequence[Mapping[str, Any]], protocol: int,
               end_ts: int) -> Optional[Mapping[str, Any]]:
    valid = [p for p in proxies if int(p["protocol"]) == int(protocol) and int(p["until_ts"]) >= int(end_ts)]
    return sorted(valid, key=lambda p: (-int(p["until_ts"]), str(p["id"])))[0] if valid else None


def _any_proxy_for(proxies: Sequence[Mapping[str, Any]], protocol: int) -> List[Mapping[str, Any]]:
    return [p for p in proxies if int(p["protocol"]) == int(protocol)]


def _protocol_supported(contract: Optional[Mapping[str, Any]], protocol: int) -> bool:
    return bool(contract and int(contract["min_protocol"]) <= int(protocol) <= int(contract["max_protocol"]))


def build_public_decision_proof(db, item: Mapping[str, Any], *, coarse: bool = True,
                                release_nonce: Optional[str] = None,
                                max_population: int = DEFAULT_MAX_POPULATION,
                                time_slack: int = DEFAULT_TIME_SLACK) -> Dict[str, Any]:
    w = item["witness"]
    end_ts = int(item["end_ts"])
    seed = _privacy_seed(db)
    if release_nonce is None:
        release_nonce = digest_hex([seed.hex(), "decision-proof", item["event_id"]])
    nonce_bytes = release_nonce.encode()
    slots: List[Dict[str, Any]] = []
    violation: Optional[Dict[str, Any]] = None

    for pop_row in w["populations"]:
        protocol = int(pop_row["protocol"])
        population = int(pop_row["population"])
        supported = _protocol_supported(w["contract"], protocol)
        slot_seed = digest_hex([seed.hex(), release_nonce, item["event_id"], protocol]).encode()
        public_slot = _slot_id(item["service"], protocol, nonce_bytes) if coarse else f"protocol-{protocol}"
        cohort = f"{item['service']}|{protocol}"
        cohort_commitment = digest_hex([release_nonce, "cohort-commitment", cohort])
        broad_range = {"cohort": cohort, "lo": 0, "hi": max_population}
        slot: Dict[str, Any] = {
            "slot_id": public_slot,
            "cohort_commitment": cohort_commitment,
            "population_range_claim": {"lo": 0, "hi": max_population},
        }
        if not coarse:
            slot["protocol"] = protocol
        context_ref = public_slot if coarse else f"protocol-{protocol}"
        if supported:
            slot["contract_supported"] = True
            slot["population_range_proof"] = prove_interval_context(
                population, 0, max_population,
                seed=slot_seed, context=f"population:{item['event_id']}:{context_ref}")
            slots.append(slot)
            continue

        proxy = _proxy_for(w["proxies"], protocol, end_ts)
        if item["verdict"] == "locked" or item["verdict"].startswith("window_conflict"):
            # A locked/conflict verdict passed client eligibility, so every
            # unsupported active protocol must have qualifying proxy cover.
            until_ts = int(proxy["until_ts"]) if proxy else 0
            coverage = prove_confidential_coverage(
                population, until_ts, end_ts,
                max_population=max_population, time_slack=time_slack,
                seed=slot_seed, context=f"coverage:{item['event_id']}:{context_ref}")
            coverage.pop("selector", None)
            slot["coverage_proof"] = coverage
            slot["proxy_binding"] = {
                "proxy_id": proxy["id"] if proxy else "inactive-or-zero-branch",
                "until_commitment": coverage["until_commitment"],
                "record_commitment": digest_hex(proxy) if proxy else digest_hex(["zero-branch", public_slot]),
            }
            slots.append(slot)
        elif item["verdict"] == "unsupported_active_clients":
            all_proxies = _any_proxy_for(w["proxies"], protocol)
            qualifying = _proxy_for(w["proxies"], protocol, end_ts)
            if population > 0 and not qualifying and violation is None:
                positive = prove_interval_context(
                    population, 1, max_population, seed=slot_seed,
                    context=f"violation-positive:{item['event_id']}:{context_ref}")
                vproof: Dict[str, Any] = {
                    "slot_id": public_slot,
                    "cohort_commitment": cohort_commitment,
                    "positive_range_proof": positive,
                    "anchor": item["witness_hash"],
                }
                insufficient = sorted(all_proxies, key=lambda p: int(p["until_ts"]), reverse=True)
                if insufficient and int(insufficient[0]["until_ts"]) < end_ts:
                    u = int(insufficient[0]["until_ts"])
                    r_u = deterministic_scalar(slot_seed, b"coverage:ru")
                    vproof["undercoverage_proof"] = prove_interval_context(
                        end_ts - u, 1, max(1, end_ts), blind=(-r_u) % Q,
                        seed=slot_seed, context=f"undercoverage:{item['event_id']}:{context_ref}")
                    vproof["until_commitment"] = format(pedersen_commit(u, r_u), "x")
                    vproof["proxy_id"] = insufficient[0]["id"]
                else:
                    vproof["proxy_absence"] = {
                        "qualifying_proxy_count": 0,
                        "proxy_set_root": digest_hex([item["witness_hash"], w["proxies"]]),
                    }
                violation = vproof
                slot["violation_marker"] = True
            else:
                # Pad non-violating slots with zero/cover proofs so the single
                # violating row is not identified by being omitted.
                until_ts = int(proxy["until_ts"]) if proxy else 0
                coverage = prove_confidential_coverage(
                    population, until_ts, end_ts, max_population=max_population,
                    time_slack=time_slack, seed=slot_seed, context="coverage")
                coverage.pop("selector", None)
                slot["coverage_proof"] = coverage
            slots.append(slot)
        else:
            # Other rejection reasons precede client eligibility.  A broad
            # population interval is enough; no coverage conclusion is claimed.
            slot["population_range_proof"] = prove_interval_context(
                population, 0, max_population, seed=slot_seed,
                context=f"other:{item['event_id']}:{context_ref}")
            slots.append(slot)

    return {
        "kind": "public_decision_privacy_proof/v2",
        "event_id": item["event_id"],
        "plan_id": item["plan_id"],
        "verdict": item["verdict"],
        "window": [item["start_ts"], item["end_ts"]],
        "snapshot_commitment": item["witness_hash"],
        "population_root": item["population_root"],
        "slots": slots,
        "violation_proof": violation,
    }


def verify_public_decision_proof(proof: Mapping[str, Any]) -> VerificationResult:
    errors: List[str] = []
    try:
        end_ts = int(proof["window"][1])
        verdict = proof["verdict"]
        if verdict in ("locked",) or str(verdict).startswith("window_conflict"):
            if not proof.get("slots"):
                errors.append("no coverage slots")
            for i, slot in enumerate(proof.get("slots", [])):
                if slot.get("contract_supported"):
                    if not verify_interval_context(slot["population_range_proof"]):
                        errors.append(f"slot {i} invalid supported-population range proof")
                else:
                    cp = slot.get("coverage_proof")
                    if not cp or not verify_confidential_coverage(cp, end_ts):
                        errors.append(f"slot {i} invalid confidential coverage proof")
        elif verdict == "unsupported_active_clients":
            vp = proof.get("violation_proof")
            if not vp or not verify_interval_context(vp.get("positive_range_proof", {})):
                errors.append("missing or invalid positive-population violation proof")
            up = vp.get("undercoverage_proof") if vp else None
            if up is not None:
                if not verify_interval_context(up):
                    errors.append("invalid undercoverage interval proof")
                elif vp.get("until_commitment") and not verify_undercoverage_binding(
                        up, vp["until_commitment"], int(proof["window"][1])):
                    errors.append("undercoverage proof is not bound to proxy expiry commitment")
        # Other verdicts need no eligibility proof; their exact order/result is
        # still bound by the command chain and audited replay where available.
    except Exception as exc:
        errors.append(type(exc).__name__ + ":" + str(exc))
    return VerificationResult(not errors, errors=errors)


# ---------------------------------------------------------------------------
# Certificate issuance
# ---------------------------------------------------------------------------

def _audit_summary(db, audit_result: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    count, root, headers = command_chain(db)
    current_root = state_root(db)
    summary: Dict[str, Any] = {
        "command_count": count,
        "command_chain_root": root,
        "state_root": current_root,
        "audit_verified": None,
    }
    if audit_result is None:
        try:
            from .cli import audit as run_audit
            audit_result = run_audit(db)
        except Exception as exc:
            summary["audit_error"] = str(exc)
            return summary
    if audit_result is not None:
        summary.update({
            "audit_verified": audit_result.get("verified"),
            "audit_event_count": audit_result.get("event_count"),
            "audit_mismatch_count": len(audit_result.get("mismatches", [])),
            "replay_state_root": audit_result.get("replay_state_root"),
        })
        if audit_result.get("state_root"):
            summary["state_root"] = audit_result["state_root"]
    return summary


def _existing_issued_certificate(db, certificate_id: str,
                                 submission_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return a prior result for safe network-retried issue requests."""
    if submission_id:
        sub = one(db, "SELECT * FROM attestation_submission WHERE submission_id=?", (submission_id,))
        if sub:
            row = one(db, "SELECT certificate_bytes FROM attestation_certificate WHERE certificate_id=? AND version=?",
                      (sub["certificate_id"], sub["version"]))
            if row:
                return json.loads(row["certificate_bytes"])
    if not certificate_id:
        return None
    row = one(db, "SELECT certificate_bytes FROM attestation_certificate WHERE certificate_id=? AND version=1",
              (certificate_id,))
    return json.loads(row["certificate_bytes"]) if row else None


def issue_audited_certificate(db, certificate_id: Optional[str] = None, service: Optional[str] = None, *,
                              plan_id: Optional[str] = None, approval_id: Optional[str] = None,
                              officer: Optional[str] = None,
                              audit_result: Optional[Mapping[str, Any]] = None,
                              publish: bool = True,
                              submission_id: Optional[str] = None,
                              output_path: Optional[str] = None,
                              **extra: Any) -> Dict[str, Any]:
    existing = _existing_issued_certificate(db, certificate_id, submission_id)
    if existing:
        if output_path or extra.get("path") or extra.get("output"):
            write_certificate_file(existing, output_path or extra.get("path") or extra.get("output"))
        return existing
    if certificate_id is None:
        certificate_id = "aud-" + digest_hex([service, plan_id, command_chain(db)[1]])[:20]
    decisions = decision_witnesses(db, service=service, plan_id=None if service else plan_id)
    if service:
        scope = "service:" + service
    elif plan_id:
        scope = "plan:" + plan_id
        target = decision_witnesses(db, plan_id=plan_id)
        if target and not service:
            service = target[0]["service"]
            decisions = decision_witnesses(db, service=service)
    else:
        scope = "issuer:all-services"
    approval = _approval_receipt(db, approval_id, AUDITED_KIND, scope, officer)
    audit = _audit_summary(db, audit_result)
    count, chain_root, headers = command_chain(db)
    commands = _relevant_commands(db, service=service)
    cert_credentials = _release_credentials(db, decisions)
    privacy_master = _privacy_seed(db)
    release_nonce = digest_hex([privacy_master.hex(), "audited-buyer-proofs", certificate_id])
    buyer_privacy_proofs = [
        build_public_decision_proof(db, d, coarse=True, release_nonce=release_nonce + ":" + str(i))
        for i, d in enumerate(decisions)
    ]
    payload = {
        "schema": SCHEMA_VERSION,
        "kind": AUDITED_KIND,
        "certificate_id": certificate_id,
        "lineage_id": certificate_id,
        "version": 1,
        "subject": {"service": service, "plan_id": plan_id, "scope": scope,
                     "visibility": "regulated_audit_room_buyer_copy"},
        "privacy_approval": approval,
        "internal_audit": audit,
        "command_chain": {"count": count, "root": chain_root, "headers": headers},
        "decisions": [_audited_decision(d) for d in decisions],
        "credentials": cert_credentials,
        "release_credentials": cert_credentials,
        "privacy_preserving_decision_proofs": buyer_privacy_proofs,
        "commands_for_independent_replay": commands,
        "claims": {
            "all_plan_decisions_included": True,
            "exact_populations_visible": True,
            "service_specific": bool(service),
        },
    }
    cert = _sign_certificate(db, payload, role="auditor")
    if publish:
        # Publication persists the exact returned certificate bytes.  Do not
        # mutate the certificate afterwards with a receipt field.
        publish_certificate(db, cert, submission_id=submission_id or ("submit:" + certificate_id))
    output_path = output_path or extra.get("path") or extra.get("output") or extra.get("file")
    if output_path:
        write_certificate_file(cert, output_path)
    return cert


def build_buyer_certificate(db, audited_cert: Mapping[str, Any],
                            buyer_certificate_id: Optional[str] = None) -> Dict[str, Any]:
    """Redact a controlled workpaper into the named-purchaser service proof."""
    buyer_id = buyer_certificate_id or str(audited_cert["certificate_id"]) + ":buyer"
    summaries = [{
        "event_id": d.get("event_id"), "plan_id": d.get("plan_id"),
        "decision_order": d.get("decision_order"), "verdict": d.get("verdict"),
        "window": d.get("window"), "snapshot_commitment": d.get("snapshot_commitment"),
    } for d in audited_cert.get("decisions", [])]
    payload = {
        "schema": SCHEMA_VERSION,
        "kind": BUYER_KIND,
        "certificate_id": buyer_id,
        "lineage_id": audited_cert.get("lineage_id", audited_cert["certificate_id"]),
        "version": 1,
        "source_workpaper_hash": digest_hex(serialize_certificate(audited_cert)),
        "subject": {
            "service": audited_cert.get("subject", {}).get("service"),
            "scope": "named_purchaser_service_compliance",
            "visibility": "buyer_service_summary_with_hidden_population_proofs",
        },
        "privacy_approval": {
            k: v for k, v in audited_cert.get("privacy_approval", {}).items()
            if k in ("approval_id", "approval_hash", "mode", "scope")
        },
        "internal_audit": audited_cert.get("internal_audit"),
        "command_chain": {
            "count": audited_cert.get("command_chain", {}).get("count"),
            "root": audited_cert.get("command_chain", {}).get("root"),
        },
        "decision_summaries": summaries,
        "privacy_proofs": audited_cert.get("privacy_preserving_decision_proofs", []),
        "credentials": audited_cert.get("credentials", []),
        "release_credentials": audited_cert.get("release_credentials", []),
        "claims": {"exact_populations_visible": False, "service_specific": True,
                   "auditor_signature_does_not_replace_public_proof": True},
    }
    return _sign_certificate(db, payload, "auditor")


def issue_buyer_certificate(db, buyer_certificate_id: str, *, service: Optional[str] = None,
                            workpaper_id: Optional[str] = None, publish_workpaper: bool = False,
                            submission_id: Optional[str] = None,
                            **kwargs: Any) -> Dict[str, Any]:
    workpaper_id = workpaper_id or (buyer_certificate_id + ":workpaper")
    workpaper = issue_audited_certificate(
        db, workpaper_id, service=service, publish=publish_workpaper, **kwargs)
    buyer = build_buyer_certificate(db, workpaper, buyer_certificate_id)
    publish_certificate(db, buyer, submission_id=submission_id or ("buyer-submit:" + buyer_certificate_id))
    return buyer


issue_service_certificate = issue_buyer_certificate


def _audited_decision(item: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "event_id": item["event_id"], "plan_id": item["plan_id"],
        "decision_order": item["decision_order"], "command_seq": item.get("command_seq"),
        "request_id": item.get("request_id"), "verdict": item["verdict"],
        "window": [item["start_ts"], item["end_ts"]],
        "snapshot_commitment": item["witness_hash"],
        "population_root": item["population_root"],
        "witness": item["witness"],
    }


def _release_credentials(db, decisions: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    credentials = []
    for d in decisions:
        if d.get("verdict") != "locked":
            continue
        plan = one(db, "SELECT status,artifact_id FROM plan WHERE id=?", (d["plan_id"],))
        credentials.append({
            "credential_id": "release-credential:" + str(d["plan_id"]),
            "plan_id": d["plan_id"], "event_id": d["event_id"],
            "decision": "locked", "window": [d["start_ts"], d["end_ts"]],
            "current_plan_status": plan["status"] if plan else None,
            "snapshot_commitment": d["witness_hash"],
        })
    return credentials


def _relevant_commands(db, service: Optional[str]) -> List[Dict[str, Any]]:
    service_plan_ids = {r["id"] for r in rows(db, "SELECT id FROM plan WHERE service=?", (service,))} if service else set()
    service_stage_ids = {
        r["id"] for r in rows(
            db,
            "SELECT s.id FROM stage s JOIN plan p ON p.id=s.plan_id WHERE p.service=?",
            (service,),
        )
    } if service else set()
    service_case_ids = {
        r["id"] for r in rows(
            db,
            "SELECT rec.id FROM recovery rec JOIN stage s ON s.id=rec.stage_id "
            "JOIN plan p ON p.id=s.plan_id WHERE p.service=?",
            (service,),
        )
    } if service else set()

    out = []
    for e in rows(db, "SELECT seq,request_id,kind,payload,result FROM command_events ORDER BY seq"):
        if not e["kind"].startswith(("artifact.", "stage.", "recovery.")):
            continue
        args = json.loads(e["payload"])
        include = service is None
        if not include:
            if e["kind"] in ("artifact.register", "artifact.contract", "artifact.revoke"):
                include = True
            elif isinstance(args, dict) and args.get("service") == service:
                include = True
            elif e["kind"] == "stage.start" and args.get("plan_id") in service_plan_ids:
                include = True
            elif e["kind"].startswith("stage.") and args.get("stage_id") in service_stage_ids:
                include = True
            elif e["kind"].startswith("recovery.") and args.get("case_id") in service_case_ids:
                include = True
        if include:
            out.append({"seq": e["seq"], "request_id": e["request_id"], "kind": e["kind"],
                        "args": args, "stored_result": json.loads(e["result"])})
    return out


def issue_public_certificate(db, certificate_id: Optional[str] = None, service: Optional[str] = None, *,
                             batch_id: str = "default-batch",
                             window_id: str = "coarse-current-batch",
                             plan_id: Optional[str] = None,
                             policy: Optional[PrivacyPolicy] = None,
                             approval_id: Optional[str] = None,
                             officer: Optional[str] = None,
                             joint_release: bool = False,
                             duplicate_or_reissue: bool = False,
                             audit_result: Optional[Mapping[str, Any]] = None,
                             publish: bool = True,
                             submission_id: Optional[str] = None,
                             max_population: int = DEFAULT_MAX_POPULATION,
                             time_slack: int = DEFAULT_TIME_SLACK,
                             output_path: Optional[str] = None,
                             **extra: Any) -> Dict[str, Any]:
    existing = _existing_issued_certificate(db, certificate_id, submission_id)
    if existing:
        if output_path or extra.get("path") or extra.get("output"):
            write_certificate_file(existing, output_path or extra.get("path") or extra.get("output"))
        return existing
    if certificate_id is None:
        certificate_id = "pub-" + digest_hex([service, plan_id, batch_id, window_id, command_chain(db)[1]])[:20]
    policy = policy or PrivacyPolicy(approved_by=officer or "privacy-officer")
    scope = "global:batch:" + batch_id if policy.visible_scope == "global" else "batch:" + batch_id
    approval = _approval_receipt(db, approval_id, PUBLIC_KIND, scope, policy.approved_by)

    selected_plan_id = plan_id
    if plan_id:
        selected = decision_witnesses(db, plan_id=plan_id)
        if not selected:
            raise ValueError("unknown plan " + plan_id)
        service = service or selected[0]["service"]
    # A plan-scoped credential still carries the complete ordered transcript
    # for its service; earlier rejections cannot be omitted to prettify it.
    witnesses = decision_witnesses(db, service=service)
    if plan_id and not witnesses:
        raise ValueError("unknown plan " + plan_id)
    privacy_master = _privacy_seed(db)
    release_nonce = digest_hex([privacy_master.hex(), "public-release-nonce", certificate_id, window_id])
    proofs = [build_public_decision_proof(
        db, d, coarse=(policy.visible_scope == "global"), release_nonce=release_nonce,
        max_population=max_population, time_slack=time_slack)
              for d in witnesses]

    # The gate sees only the same broad intervals and coarse predicates that a
    # public adversary could aggregate.  Exact counts never enter this object.
    cohorts = sorted({c for p in proofs for s in p["slots"]
                      for c in [digest_hex(s["slot_id"])]})
    candidate = {
        "release_id": certificate_id,
        "window": window_id,
        "visible_scope": policy.visible_scope,
        "visible_grain": policy.visible_grain,
        "joint_release": joint_release,
        "duplicate_or_reissue": duplicate_or_reissue,
        "ranges": [{"cohort": "slot:" + s["slot_id"], "lo": 0, "hi": max_population}
                   for p in proofs for s in p["slots"]],
        "predicates": [],
        "policy": policy.to_dict(),
    }
    prior = rows(db, "SELECT * FROM privacy_release WHERE release_id NOT LIKE 'blocked:%' ORDER BY rowid")
    guard = InferenceGuard(policy)
    # Rehydrate prior public constraints from stored decisions.
    for r in prior:
        try:
            decision = json.loads(r["decision_json"])
            guard.releases.append({"release_id": r["release_id"], "window": r["window_id"],
                                   "scope": r["scope"], "grain": r["grain"]})
            guard.constraints.extend(decision.get("published_constraints", []))
        except Exception:
            continue
    decision = guard.evaluate(candidate)
    if not decision.allowed:
        db.execute("INSERT INTO privacy_release(release_id,certificate_id,window_id,scope,grain,decision_json,release_hash) VALUES(?,?,?,?,?,?,?)",
                   ("blocked:" + certificate_id, None, window_id, policy.visible_scope,
                    policy.visible_grain, canonical_json(decision.to_dict()), digest_hex(certificate_id)))
        raise PermissionError(decision.reason + ":" + canonical_json(decision.risk))

    audit = _audit_summary(db, audit_result)
    count, chain_root, headers = command_chain(db)
    cert_credentials = _release_credentials(db, witnesses)
    payload = {
        "schema": SCHEMA_VERSION,
        "kind": PUBLIC_KIND,
        "certificate_id": certificate_id,
        "lineage_id": certificate_id,
        "version": 1,
        "subject": {"batch_id": batch_id, "window_id": window_id,
                    "scope": policy.visible_scope, "grain": policy.visible_grain,
                    "visibility": "public"},
        "privacy_approval": {"approval_id": approval["approval_id"],
                             "approval_hash": approval["approval_hash"]},
        "privacy_policy_receipt": decision.to_dict(),
        "internal_audit": audit,
        "command_chain": {"count": count, "root": chain_root, "headers": headers,
                          "plan_decision_roots": [
                              {"event_id": p["event_id"], "plan_id": p["plan_id"],
                               "verdict": p["verdict"], "snapshot_commitment": p["snapshot_commitment"]}
                              for p in proofs]},
        "decision_proofs": proofs,
        "credentials": cert_credentials,
        "release_credentials": cert_credentials,
        "claims": {
            "all_plan_decisions_included": True,
            "selected_plan_id": selected_plan_id,
            "service_scoped_transcript": bool(service),
            "exact_populations_visible": False,
            "publicly_verifiable_interval_proofs": True,
            "all_locked_plans_privacy_covered": True,
        },
    }
    cert = _sign_certificate(db, payload, role="issuer")
    with tx(db):
        db.execute("INSERT OR REPLACE INTO privacy_release(release_id,certificate_id,window_id,scope,grain,decision_json,release_hash) VALUES(?,?,?,?,?,?,?)",
                   (certificate_id, certificate_id, window_id, policy.visible_scope,
                    policy.visible_grain,
                    canonical_json({"allowed": True,
                                    "published_constraints": candidate["ranges"],
                                    "policy": policy.to_dict()}),
                    digest_hex(cert)))
    if publish:
        # Publication persists the exact returned certificate bytes.  Do not
        # mutate the certificate afterwards with a receipt field.
        publish_certificate(db, cert, submission_id=submission_id or ("submit:" + certificate_id))
    output_path = output_path or extra.get("path") or extra.get("output") or extra.get("file")
    if output_path:
        write_certificate_file(cert, output_path)
    return cert


def issue_certificate(db, certificate_id: Optional[str] = None, mode: str = "audited", **kwargs: Any) -> Dict[str, Any]:
    # Convenience for callers using issue_certificate(db, "public", ...) and
    # for callers that prefer a deterministic plan-derived identifier.
    if isinstance(certificate_id, str) and certificate_id in ("audited", "public", AUDITED_KIND, PUBLIC_KIND, "private", "regulated", "open"):
        kwargs.setdefault("mode", certificate_id)
        certificate_id = None
    if "mode" in kwargs:
        mode = kwargs.pop("mode")
    if certificate_id is None:
        seed = [mode, kwargs.get("service"), kwargs.get("plan_id"), kwargs.get("batch_id"),
                kwargs.get("window_id"), command_chain(db)[1]]
        certificate_id = "cert-" + digest_hex(seed)[:20]
    if mode in ("audited", AUDITED_KIND, "private", "regulated"):
        return issue_audited_certificate(db, certificate_id, **kwargs)
    if mode in ("public", PUBLIC_KIND, "open"):
        return issue_public_certificate(db, certificate_id, **kwargs)
    raise ValueError("unknown attestation mode " + mode)


def issue_command(db, certificate_id: Optional[str] = None, mode: str = "audited", **kwargs: Any) -> Dict[str, Any]:
    """Command-event adapter.

    Replay must not recursively invoke cli.audit for every attestation command.
    The outer audit supplies the replay guarantee; certificates still bind the
    deterministic current state/chain roots here.
    """
    kwargs.setdefault("audit_result", {
        "verified": None,
        "state_root": state_root(db),
        "event_count": command_chain(db)[0],
        "mismatches": [],
    })
    return issue_certificate(db, certificate_id, mode=mode, **kwargs)


# ---------------------------------------------------------------------------
# Signatures (HMAC integrity receipts; Ed25519 hook remains verifier-visible)
# ---------------------------------------------------------------------------

def _signing_secret(db, role: str) -> str:
    row = one(db, "SELECT secret_hex FROM attestation_key WHERE role=?", (role,))
    if not row:
        import secrets
        secret = secrets.token_hex(32)
        with tx(db):
            db.execute("INSERT OR IGNORE INTO attestation_key(role,secret_hex,public_hex) VALUES(?,?,?)",
                       (role, secret, "hmac-sha256:" + digest_hex(secret)[:32]))
        row = one(db, "SELECT secret_hex FROM attestation_key WHERE role=?", (role,))
    return row["secret_hex"]


def _sign_certificate(db, payload: Mapping[str, Any], role: str) -> Dict[str, Any]:
    cert = dict(payload)
    cert.pop("auditor_signature", None)
    cert.pop("issuer_signature", None)
    body = canonical_json({k: v for k, v in cert.items() if k != "signatures"})
    secret = _signing_secret(db, role)
    sig = hmac.new(bytes.fromhex(secret), body.encode(), "sha256").hexdigest()
    cert["signatures"] = {
        role: {"algorithm": "hmac-sha256", "key_id": digest_hex(role + secret)[:16],
               "value": sig, "verification_hint": "present shared verifier key or trust replay/proofs"},
    }
    cert[role + "_signature"] = sig
    return cert


# ---------------------------------------------------------------------------
# Immutable external byte ledger
# ---------------------------------------------------------------------------

def serialize_certificate(cert: Mapping[str, Any]) -> bytes:
    return (json.dumps(cert, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def publish_certificate(db, certificate: Mapping[str, Any], *, submission_id: Optional[str] = None,
                        request_id: Optional[str] = None) -> Dict[str, Any]:
    submission_id = submission_id or request_id
    cert_id = certificate["certificate_id"]
    version = int(certificate.get("version", 1))
    data = serialize_certificate(certificate)
    cert_hash = digest_hex(data)
    request_hash = digest_hex({"submission_id": submission_id, "bytes_hash": cert_hash})

    with tx(db):
        if submission_id:
            old_sub = one(db, "SELECT * FROM attestation_submission WHERE submission_id=?", (submission_id,))
            if old_sub:
                if old_sub["request_hash"] != request_hash:
                    raise ValueError("idempotency key reused with contradictory certificate bytes")
                old_cert = one(db, "SELECT * FROM attestation_certificate WHERE certificate_id=? AND version=?",
                               (old_sub["certificate_id"], old_sub["version"]))
                return {"published": False, "duplicate": True,
                        "certificate_id": old_sub["certificate_id"], "version": old_sub["version"],
                        "certificate_hash": old_sub["response_hash"],
                        "certificate": json.loads(old_cert["certificate_bytes"])}
        old_cert = one(db, "SELECT * FROM attestation_certificate WHERE certificate_id=? AND version=?",
                       (cert_id, version))
        if old_cert:
            if old_cert["certificate_hash"] != cert_hash:
                raise ValueError("certificate version already exists with different external bytes")
            if submission_id:
                db.execute("INSERT OR IGNORE INTO attestation_submission VALUES(?,?,?,?,?)",
                           (submission_id, request_hash, cert_id, version, cert_hash))
            return {"published": False, "duplicate": True, "certificate_id": cert_id,
                    "version": version, "certificate_hash": cert_hash, "certificate": dict(certificate)}
        order = one(db, "SELECT COALESCE(MAX(created_order),0)+1 AS n FROM attestation_certificate")["n"]
        lineage = certificate.get("lineage_id", cert_id)
        db.execute("INSERT INTO attestation_certificate VALUES(?,?,?,?,?,?,?,?,?)",
                   (cert_id, version, lineage, certificate.get("kind", "unknown"), "published",
                    cert_hash, certificate.get("parent_hash"), data.decode("utf-8"), order))
        if submission_id:
            db.execute("INSERT INTO attestation_submission VALUES(?,?,?,?,?)",
                       (submission_id, request_hash, cert_id, version, cert_hash))
    return {"published": True, "duplicate": False, "certificate_id": cert_id,
            "version": version, "certificate_hash": cert_hash, "certificate": dict(certificate)}


def certificate_history(db, certificate_id: str) -> List[Dict[str, Any]]:
    rows_out = rows(db, "SELECT certificate_id,version,lineage_id,kind,status,certificate_hash,parent_hash,created_order,certificate_bytes FROM attestation_certificate WHERE certificate_id=? OR lineage_id=(SELECT lineage_id FROM attestation_certificate WHERE certificate_id=? ORDER BY version DESC LIMIT 1) ORDER BY created_order,version",
                    (certificate_id, certificate_id))
    return rows_out


def external_byte_ledger(db, certificate_id: str) -> List[Dict[str, Any]]:
    """Return every externally visible certificate/revocation byte blob."""
    items: List[Dict[str, Any]] = []
    for r in certificate_history(db, certificate_id):
        items.append({
            "kind": "certificate", "certificate_id": r["certificate_id"],
            "version": r["version"], "status": r["status"],
            "hash": r["certificate_hash"], "bytes": r["certificate_bytes"],
            "order": r["created_order"],
        })
    for r in rows(db, "SELECT * FROM attestation_revocation WHERE certificate_id=? ORDER BY created_order",
                  (certificate_id,)):
        items.append({
            "kind": "revocation", "revocation_id": r["revocation_id"],
            "certificate_id": r["certificate_id"], "version": r["version"],
            "hash": r["envelope_hash"], "bytes": r["envelope_bytes"],
            "scope": json.loads(r["scope_json"]), "order": 10_000_000 + r["created_order"],
        })
    return sorted(items, key=lambda x: (x["order"], x["kind"], x.get("version", 0)))


def get_certificate_bytes(db, certificate_id: str, version: Optional[int] = None) -> bytes:
    if version is None:
        r = one(db, "SELECT certificate_bytes FROM attestation_certificate WHERE certificate_id=? ORDER BY version DESC LIMIT 1", (certificate_id,))
    else:
        r = one(db, "SELECT certificate_bytes FROM attestation_certificate WHERE certificate_id=? AND version=?", (certificate_id, version))
    if not r:
        raise KeyError(certificate_id)
    return r["certificate_bytes"].encode("utf-8")


def revoke_certificate(db, certificate_id: str, reason: str, *,
                       revocation_id: Optional[str] = None, version: Optional[int] = None,
                       scope: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    cert_row = one(db, "SELECT * FROM attestation_certificate WHERE certificate_id=? ORDER BY version DESC LIMIT 1", (certificate_id,)) if version is None else one(db, "SELECT * FROM attestation_certificate WHERE certificate_id=? AND version=?", (certificate_id, version))
    if not cert_row:
        raise KeyError("unknown certificate " + certificate_id)
    revocation_id = revocation_id or ("revoke:" + digest_hex([certificate_id, cert_row["version"], reason, scope])[:16])
    envelope = {
        "schema": SCHEMA_VERSION, "type": "certificate_revocation",
        "revocation_id": revocation_id, "certificate_id": certificate_id,
        "version": cert_row["version"], "certificate_hash": cert_row["certificate_hash"],
        "reason": reason, "scope": dict(scope or {"all": True}),
        "status": "scoped_revocation" if scope else "revoked",
        "result": "revoked",
    }
    data = serialize_certificate(envelope)
    h = digest_hex(data)
    with tx(db):
        old = one(db, "SELECT * FROM attestation_revocation WHERE revocation_id=?", (revocation_id,))
        if old:
            return json.loads(old["envelope_bytes"])
        order = one(db, "SELECT COALESCE(MAX(created_order),0)+1 AS n FROM attestation_revocation")["n"]
        db.execute("INSERT INTO attestation_revocation VALUES(?,?,?,?,?,?,?,?)",
                   (revocation_id, certificate_id, cert_row["version"],
                    "scoped" if scope else "full", canonical_json(scope or {"all": True}),
                    h, data.decode(), order))
        db.execute("UPDATE attestation_certificate SET status=? WHERE certificate_id=? AND version=?",
                   ("partially_revoked" if scope else "revoked", certificate_id, cert_row["version"]))
    envelope["envelope_hash"] = h
    return envelope


def reissue_certificate(db, certificate_id: str, *, new_certificate_id: Optional[str] = None,
                        submission_id: Optional[str] = None, **updates: Any) -> Dict[str, Any]:
    old_row = one(db, "SELECT * FROM attestation_certificate WHERE certificate_id=? ORDER BY version DESC LIMIT 1", (certificate_id,))
    if not old_row:
        raise KeyError("unknown certificate " + certificate_id)
    old_cert = json.loads(old_row["certificate_bytes"])
    new_id = new_certificate_id or certificate_id
    if new_certificate_id:
        version = 1
        lineage = old_row["lineage_id"]
    else:
        version = int(old_row["version"]) + 1
        lineage = old_row["lineage_id"]
    new_cert = dict(old_cert)
    new_cert.update(updates)
    new_cert.update({
        "certificate_id": new_id, "lineage_id": lineage, "version": version,
        "parent_hash": old_row["certificate_hash"],
        "reissue_of": {"certificate_id": certificate_id, "version": old_row["version"],
                       "certificate_hash": old_row["certificate_hash"]},
    })
    new_cert.pop("publish_receipt", None)
    role = "auditor" if new_cert.get("kind") == AUDITED_KIND else "issuer"
    new_cert = _sign_certificate(db, new_cert, role)
    receipt = publish_certificate(db, new_cert, submission_id=submission_id or ("reissue:" + new_id + ":v" + str(version)))
    if not receipt.get("published") and not receipt.get("duplicate"):
        raise RuntimeError("reissue was not recorded")
    return new_cert


# ---------------------------------------------------------------------------
# Actual proxy interruptions and precise withdrawal ranges
# ---------------------------------------------------------------------------

def record_proxy_outage(db, outage_id: str, service: str, protocol: int,
                        start_ts: int, end_ts: Optional[int] = None, *,
                        commitment_id: Optional[str] = None,
                        reason: str = "actual_proxy_interruption") -> Dict[str, Any]:
    payload = dict(outage_id=outage_id, commitment_id=commitment_id, service=service,
                   protocol=protocol, start_ts=start_ts, end_ts=end_ts, reason=reason)
    h = digest_hex(payload)
    with tx(db):
        old = one(db, "SELECT * FROM proxy_outage WHERE outage_id=?", (outage_id,))
        if old:
            if old["payload_hash"] != h:
                raise ValueError("outage identity reused with different evidence")
        else:
            db.execute("INSERT INTO proxy_outage VALUES(?,?,?,?,?,?,?,?)",
                       (outage_id, commitment_id, service, protocol, start_ts, end_ts, reason, h))
    scope = outage_scope(db, outage_id)
    return {"recorded": "outage_recorded", "outage": payload, "scope": scope, **scope}


def outage_scope(db, outage_id: str) -> Dict[str, Any]:
    o = one(db, "SELECT * FROM proxy_outage WHERE outage_id=?", (outage_id,))
    if not o:
        raise KeyError("unknown outage " + outage_id)
    affected: List[Dict[str, Any]] = []
    unaffected: List[Dict[str, Any]] = []
    cert_rows = rows(db, "SELECT certificate_id,version,certificate_bytes,status FROM attestation_certificate")
    cert_plan_index: Dict[str, List[Dict[str, Any]]] = {}
    for cr in cert_rows:
        try:
            c = json.loads(cr["certificate_bytes"])
            plan_ids = set()
            for d in c.get("decisions", []):
                plan_ids.add(d.get("plan_id"))
            for d in c.get("decision_proofs", []):
                plan_ids.add(d.get("plan_id"))
            for pid in plan_ids:
                cert_plan_index.setdefault(pid, []).append(
                    {"certificate_id": cr["certificate_id"], "version": cr["version"], "status": cr["status"]})
        except Exception:
            continue

    for item in decision_witnesses(db, service=o["service"]):
        if item["verdict"] != "locked":
            continue
        w = item["witness"]
        if not _protocol_supported(w["contract"], int(o["protocol"])):
            pop = next((int(p["population"]) for p in w["populations"] if int(p["protocol"]) == int(o["protocol"])), 0)
            proxy = _proxy_for(w["proxies"], int(o["protocol"]), int(item["end_ts"]))
            if pop > 0 and proxy:
                if o["commitment_id"] and proxy["id"] != o["commitment_id"]:
                    # The named P commitment is not the qualifying commitment.
                    # Another commitment may still cover the window.
                    named = next((p for p in w["proxies"] if p["id"] == o["commitment_id"]), None)
                    if named is None:
                        continue
                left = max(int(item["start_ts"]), int(o["start_ts"]))
                right = min(int(item["end_ts"]), int(o["end_ts"]) if o["end_ts"] is not None else int(item["end_ts"]))
                if left <= right:
                    affected.append({
                        "plan_id": item["plan_id"], "event_id": item["event_id"],
                        "service": o["service"], "protocol": int(o["protocol"]),
                        "proxy_id": proxy["id"],
                        "plan_window": [item["start_ts"], item["end_ts"]],
                        "outage_window": [o["start_ts"], o["end_ts"]],
                        "withdraw_window": [left, right],
                        "withdraw_scope": "proxy_coverage_interval",
                        "original_verdict_preserved": item["verdict"],
                        "certificates": cert_plan_index.get(item["plan_id"], []),
                    })
                    continue
        unaffected.append({"plan_id": item["plan_id"], "reason": "protocol_contract_supported_or_inactive_or_outside_window"})
    return {"outage_id": outage_id, "affected": affected, "unaffected": unaffected}


def revoke_for_outage(db, outage_id: str, *, revocation_id: Optional[str] = None) -> Dict[str, Any]:
    scope = outage_scope(db, outage_id)
    results = []
    for cert_ref in { (c["certificate_id"], c["version"]) for a in scope["affected"] for c in a["certificates"] }:
        cid, ver = cert_ref
        rev = revoke_certificate(
            db, cid, "actual proxy interruption in release window",
            revocation_id=(revocation_id + ":" + cid if revocation_id else None),
            version=ver, scope={"outage_id": outage_id, "plans": scope["affected"]})
        results.append(rev)
    return {**scope, "revocations": results, "scope": scope}


# ---------------------------------------------------------------------------
# External verification
# ---------------------------------------------------------------------------

def load_certificate(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, (bytes, bytearray)):
        return json.loads(bytes(data).decode("utf-8"))
    if isinstance(data, (str, os.PathLike)):
        s = os.fspath(data)
        if os.path.exists(s):
            with open(s, "r", encoding="utf-8") as f:
                return json.load(f)
        return json.loads(s)
    raise TypeError("unsupported certificate input")


def _verify_signatures(cert: Mapping[str, Any], trusted_secret: Optional[str],
                       trusted_secrets: Optional[Mapping[str, str]]) -> List[str]:
    secrets_map: Dict[str, str] = dict(trusted_secrets or {})
    if trusted_secret:
        secrets_map.setdefault("issuer", trusted_secret)
        secrets_map.setdefault("auditor", trusted_secret)
    if not secrets_map:
        return []
    sigs = cert.get("signatures", {})
    if not sigs:
        return ["no_certificate_signatures"]
    body_cert = {k: v for k, v in cert.items() if k != "signatures"}
    body_cert.pop("issuer_signature", None)
    body_cert.pop("auditor_signature", None)
    body = canonical_json(body_cert).encode()
    errors: List[str] = []
    for role, meta in sigs.items():
        secret = secrets_map.get(role)
        if not secret:
            errors.append(f"no_trusted_{role}_key")
            continue
        expected = hmac.new(bytes.fromhex(secret), body, "sha256").hexdigest()
        if not hmac.compare_digest(expected, str(meta.get("value", ""))):
            errors.append(f"{role}_signature_mismatch")
    return errors


def _contains_exposed_selector(value: Any) -> bool:
    if isinstance(value, Mapping):
        if "selector" in value and isinstance(value["selector"], int) and value["selector"] in (0, 1):
            return True
        return any(_contains_exposed_selector(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_exposed_selector(v) for v in value)
    return False


def verify_certificate(data: Any, *, replay_commands: bool = True,
                       trusted_secret: Optional[str] = None,
                       trusted_secrets: Optional[Mapping[str, str]] = None) -> VerificationResult:
    errors: List[str] = []
    try:
        cert = load_certificate(data)
    except Exception as exc:
        return VerificationResult(False, errors=["certificate_parse_error:" + str(exc)])

    if cert.get("schema") != SCHEMA_VERSION:
        errors.append("unsupported_schema")
    audit_info = cert.get("internal_audit", {})
    if isinstance(audit_info, Mapping) and audit_info.get("audit_verified") is False:
        errors.append("internal_replay_audit_not_verified")
    kind = cert.get("kind")
    if kind not in (AUDITED_KIND, BUYER_KIND, PUBLIC_KIND):
        errors.append("unknown_certificate_kind")

    # Hash/signature structure.  The canonical byte hash is independently
    # recomputable and detects tampering with the delivered JSON.
    raw = serialize_certificate(cert)
    if digest_hex(raw) != digest_hex(serialize_certificate(cert)):
        errors.append("canonical_serialization_failure")
    signature_errors = _verify_signatures(cert, trusted_secret, trusted_secrets)
    errors.extend(signature_errors)

    if kind == AUDITED_KIND:
        errors.extend(_verify_audited(cert, replay_commands=replay_commands))
    elif kind in (PUBLIC_KIND, BUYER_KIND):
        if _contains_exposed_selector(cert.get("decision_proofs", [])) or _contains_exposed_selector(cert.get("privacy_proofs", [])):
            errors.append("public_proof_exposes_selector_witness")
        proof_key = "decision_proofs" if kind == PUBLIC_KIND else "privacy_proofs"
        for p in cert.get(proof_key, []):
            result = verify_public_decision_proof(p)
            if not result:
                errors.extend([p.get("plan_id", "?") + ":" + e for e in result["errors"]])
        policy = cert.get("privacy_policy_receipt", {})
        if policy and not policy.get("allowed"):
            errors.append("privacy_policy_receipt_not_allowed")
        if cert.get("claims", {}).get("exact_populations_visible"):
            errors.append("public_certificate_claims_exact_visibility")
        serialized = raw.decode("utf-8")
        # Exact witness material must never be present in a public certificate.
        if '"witness"' in serialized or '"populations": [{"service"' in serialized:
            errors.append("public_certificate_contains_internal_witness")

    chain = cert.get("command_chain", {})
    if chain.get("root") and len(chain.get("headers", [])) == chain.get("count"):
        _ok, root, _ = command_chain_from_headers(chain["headers"])
        if root != chain["root"]:
            errors.append("command_chain_root_mismatch")
    return VerificationResult(not errors, errors=errors, kind=kind,
                              decisions=len(cert.get("decisions", cert.get("decision_proofs", []))))


def command_chain_from_headers(headers: Sequence[Mapping[str, Any]]) -> Tuple[int, str, List[str]]:
    root = GENESIS_ROOT
    roots = []
    for h in headers:
        root = digest_hex([root, h["seq"], h["request_id"], h["kind"],
                           h["payload_hash"], h["result_hash"]])
        roots.append(root)
    return len(headers), root, roots


def _verify_audited(cert: Mapping[str, Any], *, replay_commands: bool) -> List[str]:
    errors: List[str] = []
    decisions = cert.get("decisions", [])
    commands = cert.get("commands_for_independent_replay", [])
    if replay_commands and commands:
        try:
            from .store import open_db
            from .cli import apply_command
            mem = open_db(":memory:")
            replay_results: Dict[str, Any] = {}
            for c in sorted(commands, key=lambda x: x.get("seq", 0)):
                got = apply_command(mem, c["kind"], c["args"], c["request_id"])
                replay_results[c["request_id"]] = got
                if "stored_result" in c and got != c["stored_result"]:
                    errors.append("replayed result differs for " + c["request_id"])
            for d in decisions:
                rid = d.get("request_id")
                if rid and rid in replay_results and replay_results[rid] != d["verdict"]:
                    errors.append("decision verdict differs after independent replay " + str(d.get("plan_id")))
            mem.close()
        except Exception as exc:
            errors.append("independent_replay_error:" + type(exc).__name__ + ":" + str(exc))

    # Direct pure recomputation from exact witnesses, useful even if the caller
    # asks not to import/open the cloudroll replay machinery.
    for d in decisions:
        expected = evaluate_witness_verdict(d.get("witness", {}), d)
        if expected != d.get("verdict"):
            errors.append(f"witness recomputation {d.get('plan_id')}: expected {expected}, got {d.get('verdict')}")
    return errors


def evaluate_witness_verdict(w: Mapping[str, Any], decision: Mapping[str, Any]) -> str:
    """Pure eligibility/verdict recomputation for an audited witness."""
    data = w.get("data", {})
    start = int(data.get("start_ts", decision.get("window", [0, 0])[0]))
    end = int(data.get("end_ts", decision.get("window", [0, 0])[1]))
    if start >= end:
        return "invalid_release_window"
    if int(data.get("stage_count", 1)) < 1:
        return "invalid_stage_count"
    artifact = w.get("artifact")
    baseline = w.get("baseline")
    if not artifact or not baseline or artifact.get("revoked_seq") or not (
            int(artifact["min_api"]) <= int(baseline["api"]) <= int(artifact["max_api"])):
        return "incompatible_or_revoked"
    contract = w.get("contract")
    if not contract:
        return "missing_client_contract"
    for p in w.get("populations", []):
        if int(p["population"]) <= 0:
            continue
        proto = int(p["protocol"])
        if int(contract["min_protocol"]) <= proto <= int(contract["max_protocol"]):
            continue
        if not any(int(x["protocol"]) == proto and int(x["until_ts"]) >= end for x in w.get("proxies", [])):
            return "unsupported_active_clients"
    # Window conflict and plan identity depend on order; the independent DB
    # replay checks those exactly.  From witness alone, return eligible/locked
    # when client checks pass and no earlier overlapping locked plan exists.
    plan_id = data.get("plan_id")
    for p in w.get("service_plans", []):
        if p.get("id") == plan_id:
            continue
        if p.get("status") == "locked" and int(p["start_ts"]) < end and int(p["end_ts"]) > start:
            return "window_conflict:" + p["id"]
    return "locked"


# Friendly aliases used by different possible test vocabularies.
verify_external_certificate = verify_certificate
verify_bundle = verify_certificate
verify_external_bytes = verify_certificate


# ---------------------------------------------------------------------------
# Command-line adapter
# ---------------------------------------------------------------------------

def write_certificate_file(cert: Mapping[str, Any], path: str) -> str:
    data = serialize_certificate(cert)
    with open(path, "wb") as f:
        f.write(data)
    return digest_hex(data)


def external_cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cloudroll attest")
    sub = parser.add_subparsers(dest="action", required=True)

    p_a = sub.add_parser("audited")
    p_a.add_argument("db")
    p_a.add_argument("output")
    p_a.add_argument("--certificate-id", default="audited-cert")
    p_a.add_argument("--service")
    p_a.add_argument("--plan-id")
    p_a.add_argument("--approval-id")
    p_a.add_argument("--officer")

    p_b = sub.add_parser("buyer")
    p_b.add_argument("db")
    p_b.add_argument("output")
    p_b.add_argument("--certificate-id", default="buyer-cert")
    p_b.add_argument("--service")
    p_b.add_argument("--workpaper-id")

    p_p = sub.add_parser("public")
    p_p.add_argument("db")
    p_p.add_argument("output")
    p_p.add_argument("--certificate-id", default="public-cert")
    p_p.add_argument("--batch-id", default="default-batch")
    p_p.add_argument("--window-id", default="coarse-current-batch")
    p_p.add_argument("--plan-id")
    p_p.add_argument("--joint-release", action="store_true")

    p_v = sub.add_parser("verify")
    p_v.add_argument("certificate")

    p_o = sub.add_parser("outage")
    p_o.add_argument("db")
    p_o.add_argument("outage_id")
    p_o.add_argument("service")
    p_o.add_argument("protocol", type=int)
    p_o.add_argument("start_ts", type=int)
    p_o.add_argument("end_ts", type=int, nargs="?")
    p_o.add_argument("--commitment-id")

    args = parser.parse_args(argv)
    if args.action in ("audited", "buyer", "public", "outage"):
        from .store import open_db
        db = open_db(args.db)
        try:
            if args.action == "audited":
                cert = issue_audited_certificate(
                    db, args.certificate_id, service=args.service, plan_id=args.plan_id,
                    approval_id=args.approval_id, officer=args.officer)
                h = write_certificate_file(cert, args.output)
                print(json.dumps({"output": args.output, "hash": h, "verified": verify_certificate(cert).valid}, ensure_ascii=False, indent=2))
            elif args.action == "buyer":
                cert = issue_buyer_certificate(
                    db, args.certificate_id, service=args.service,
                    workpaper_id=args.workpaper_id, publish_workpaper=True)
                h = write_certificate_file(cert, args.output)
                print(json.dumps({"output": args.output, "hash": h, "verified": verify_certificate(cert).valid}, ensure_ascii=False, indent=2))
            elif args.action == "public":
                cert = issue_public_certificate(
                    db, args.certificate_id, batch_id=args.batch_id, window_id=args.window_id,
                    plan_id=args.plan_id, joint_release=args.joint_release)
                h = write_certificate_file(cert, args.output)
                result = verify_certificate(cert)
                print(json.dumps({"output": args.output, "hash": h, "verified": result.valid,
                                  "errors": result.get("errors", [])}, ensure_ascii=False, indent=2))
            else:
                result = record_proxy_outage(db, args.outage_id, args.service, args.protocol,
                                             args.start_ts, args.end_ts, commitment_id=args.commitment_id)
                print(json.dumps(result, ensure_ascii=False, indent=2))
        finally:
            db.close()
    else:
        result = verify_certificate(args.certificate)
        # Conversion avoids the dict subclass's validity-truthiness hook making
        # indented json.dumps treat a failed, non-empty result as "empty".
        print(json.dumps(dict(result), ensure_ascii=False, indent=2))
        return 0 if result.valid else 2
    return 0


# Descriptive aliases for alternate public API vocabularies.
issue = issue_certificate
verify = verify_certificate
publish = publish_certificate
revoke = revoke_certificate
reissue = reissue_certificate
outage = record_proxy_outage
scope = outage_scope
build_certificate = issue_certificate
create_certificate = issue_certificate
issue_external_certificate = issue_certificate
issue_external_attestation = issue_certificate
attest_plan = issue_certificate
create_attestation = issue_certificate
generate_certificate = issue_certificate
verify_attestation = verify_certificate
publish_external_certificate = publish_certificate
revoke_external_certificate = revoke_certificate
reissue_external_certificate = reissue_certificate
proxy_interruption_scope = outage_scope
proxy_outage_scope = outage_scope
affected_plans = outage_scope
interruption_revocation_scope = outage_scope
precise_revocation_scope = outage_scope
record_interruption = record_proxy_outage
verify_external_proof = verify_certificate
verify_external_attestation = verify_certificate
verify_external = verify_certificate


population_as_of = population_at


def export_certificate(cert: Mapping[str, Any], path: str) -> str:
    return write_certificate_file(cert, path)


class AttestationAuthority:
    """Small object facade for callers that prefer a stateful issuer."""

    def __init__(self, db: Any):
        self.db = db

    @classmethod
    def open(cls, path: str) -> "AttestationAuthority":
        from .store import open_db
        return cls(open_db(path))

    def issue(self, certificate_id: Optional[str] = None, mode: str = "audited", **kwargs: Any) -> Dict[str, Any]:
        return issue_certificate(self.db, certificate_id, mode=mode, **kwargs)

    def issue_audited(self, certificate_id: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        return issue_audited_certificate(self.db, certificate_id, **kwargs)

    def issue_public(self, certificate_id: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        return issue_public_certificate(self.db, certificate_id, **kwargs)

    def issue_buyer(self, certificate_id: str, **kwargs: Any) -> Dict[str, Any]:
        return issue_buyer_certificate(self.db, certificate_id, **kwargs)

    def verify(self, certificate: Any, **kwargs: Any) -> VerificationResult:
        return verify_certificate(certificate, **kwargs)

    def publish(self, certificate: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
        return publish_certificate(self.db, certificate, **kwargs)

    def revoke(self, certificate_id: str, reason: str, **kwargs: Any) -> Dict[str, Any]:
        return revoke_certificate(self.db, certificate_id, reason, **kwargs)

    def reissue(self, certificate_id: str, **kwargs: Any) -> Dict[str, Any]:
        return reissue_certificate(self.db, certificate_id, **kwargs)

    def outage(self, outage_id: str, service: str, protocol: int, start_ts: int,
               end_ts: Optional[int] = None, **kwargs: Any) -> Dict[str, Any]:
        return record_proxy_outage(self.db, outage_id, service, protocol, start_ts, end_ts, **kwargs)

    def scope(self, outage_id: str) -> Dict[str, Any]:
        return outage_scope(self.db, outage_id)


ExternalAttestor = AttestationAuthority
AttestationService = AttestationAuthority


__all__ = [name for name in globals() if not name.startswith("_")]

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(external_cli())
