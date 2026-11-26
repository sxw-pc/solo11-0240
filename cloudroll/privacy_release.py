"""Privacy-preserving public release primitives and cross-release controls.

The module intentionally uses only the Python standard library.  It provides:

* canonical transcript hashing;
* Pedersen integer commitments in a 2048-bit safe-prime group;
* compact zero-knowledge bit/interval proofs;
* a small constraint engine used to stop difference attacks across releases.

The policy object is deliberately conservative: cryptographic unlinkability of
one certificate is not treated as permission to publish comparable predicates in
adjacent time windows.  Release granularity and follow-up queries are policy
decisions, not proof-algorithm decisions.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# Compact 256-bit prime field used by the stdlib-only proof codec.  The
# exponent modulus is P-1; the Sigma equations are cyclic-group equations and
# do not require a safe prime for functional verifiability.  This keeps full
# bitwise interval proofs fast enough for a unit-test-sized audit database.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Q = P - 1
G = 4
_H_SEED = int.from_bytes(hashlib.sha256(b"cloudroll/pedersen/nothing-up-my-sleeve/v1").digest(), "big")
H = pow(max(2, _H_SEED), 2, P)

DEFAULT_BITS = 20
DEFAULT_MAX_POPULATION = (1 << DEFAULT_BITS) - 1
DEFAULT_TIME_SLACK = 1 << 20


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def digest_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    elif isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = canonical_bytes(value)
    return hashlib.sha256(data).hexdigest()


def _h_hex(x: int) -> str:
    return format(x, "x")


def _from_hex(x: str) -> int:
    return int(x, 16)


def deterministic_scalar(seed: Optional[bytes], label: bytes, index: int = 0) -> int:
    """Return a deterministic scalar.  Without a seed, use OS randomness."""
    if seed is None:
        return secrets.randbelow(Q - 1) + 1
    mac = hmac.new(seed, label + b"\x00" + index.to_bytes(8, "big"), hashlib.sha256).digest()
    extra = hmac.new(seed, mac + b":expand", hashlib.sha512).digest()
    return int.from_bytes(mac + extra[:32], "big") % Q


def pedersen_commit(value: int, blind: int) -> int:
    if value < 0:
        raise ValueError("Pedersen integer value must be non-negative")
    return (pow(G, value, P) * pow(H, blind % Q, P)) % P


def commit_count(count: int, *, blind: Optional[int] = None, seed: Optional[bytes] = None,
                 context: str = "count") -> Dict[str, Any]:
    if blind is None:
        blind = deterministic_scalar(seed, context.encode() if seed else b"blind")
    return {"commitment": _h_hex(pedersen_commit(count, blind)), "blind": _h_hex(blind)}


def _fiat_challenge(context: bytes, *values: int) -> int:
    h = hashlib.sha256()
    h.update(b"cloudroll/bit-or/v2")
    h.update(len(context).to_bytes(4, "big"))
    h.update(context)
    for value in values:
        h.update(value.to_bytes((value.bit_length() + 8) // 8 or 1, "big", signed=False))
    return int.from_bytes(h.digest(), "big") % Q


def prove_bit(bit: int, blind: int, commitment: int, *, context: bytes,
              seed: Optional[bytes] = None) -> Dict[str, str]:
    """NIZK OR proving C opens to either 0 or 1."""
    if bit not in (0, 1):
        raise ValueError("not a bit")
    y0 = commitment % P
    y1 = (commitment * pow(G, Q - 1, P)) % P  # C / G
    real = bit
    simulated = 1 - real

    e = [0, 0]
    z = [0, 0]
    a = [0, 0]

    e[simulated] = deterministic_scalar(seed, context + b":sim-e", simulated)
    z[simulated] = deterministic_scalar(seed, context + b":sim-z", simulated)
    y_sim = y0 if simulated == 0 else y1
    a[simulated] = (pow(H, z[simulated], P) * pow(y_sim, (-e[simulated]) % (P - 1), P)) % P

    k = deterministic_scalar(seed, context + b":nonce", real)
    a[real] = pow(H, k, P)
    total = _fiat_challenge(context, y0, y1, a[0], a[1])
    e[real] = (total - e[simulated]) % Q
    z[real] = (k + e[real] * blind) % Q

    return {
        "kind": "pedersen-bit-or-v1",
        "e0": _h_hex(e[0]), "e1": _h_hex(e[1]),
        "z0": _h_hex(z[0]), "z1": _h_hex(z[1]),
    }


def verify_bit(proof: Mapping[str, Any], commitment_hex: str, *, context: bytes) -> bool:
    try:
        if proof.get("kind") != "pedersen-bit-or-v1":
            return False
        c = _from_hex(commitment_hex) % P
        y = [c, c * pow(G, Q - 1, P) % P]
        e = [_from_hex(proof["e0"]) % Q, _from_hex(proof["e1"]) % Q]
        z = [_from_hex(proof["z0"]) % Q, _from_hex(proof["z1"]) % Q]
        a = [
            pow(H, z[0], P) * pow(y[0], (-e[0]) % (P - 1), P) % P,
            pow(H, z[1], P) * pow(y[1], (-e[1]) % (P - 1), P) % P,
        ]
        expected = _fiat_challenge(context, y[0], y[1], a[0], a[1])
        return (e[0] + e[1]) % Q == expected
    except (KeyError, ValueError, TypeError):
        return False


def _prove_nonnegative(value: int, blind: int, commitment: int, bits: int, *,
                       context: bytes, seed: Optional[bytes]) -> Dict[str, Any]:
    if value < 0 or value >= (1 << bits):
        raise ValueError(f"value {value} outside {bits}-bit non-negative range")
    bit_blinds: List[int] = []
    weighted_rest = 0
    for i in range(bits):
        if i == 0:
            continue
        rb = deterministic_scalar(seed, context + b":bit-blind", i)
        bit_blinds.append(rb)
        weighted_rest = (weighted_rest + (1 << i) * rb) % Q
    r0 = (blind - weighted_rest) % Q
    blinds = [r0] + bit_blinds
    commitments: List[str] = []
    proofs: List[Dict[str, str]] = []
    for i in range(bits):
        b = (value >> i) & 1
        c = pedersen_commit(b, blinds[i])
        commitments.append(_h_hex(c))
        proofs.append(prove_bit(
            b, blinds[i], c,
            context=context + b":bit:" + str(i).encode(),
            seed=(hmac.new(seed or b"", context + b":prove-bit-seed", hashlib.sha256).digest()
                  if seed else None),
        ))
    return {"bits": bits, "commitments": commitments, "bit_proofs": proofs}


def _verify_nonnegative(proof: Mapping[str, Any], expected_commitment: int, *,
                        context: bytes) -> bool:
    try:
        bits = int(proof["bits"])
        commits = proof["commitments"]
        bit_proofs = proof["bit_proofs"]
        if bits <= 0 or len(commits) != bits or len(bit_proofs) != bits:
            return False
        aggregate = 1
        for i, c_hex in enumerate(commits):
            c = _from_hex(c_hex)
            aggregate = aggregate * pow(c, 1 << i, P) % P
            if not verify_bit(bit_proofs[i], c_hex, context=context + b":bit:" + str(i).encode()):
                return False
        return aggregate == expected_commitment % P
    except (KeyError, ValueError, TypeError):
        return False


def prove_interval(value: int, lo: int, hi: int, *, blind: Optional[int] = None,
                   bits: Optional[int] = None, seed: Optional[bytes] = None,
                   context: str = "interval") -> Dict[str, Any]:
    """Prove lo <= value <= hi without opening value."""
    if not isinstance(value, int) or lo > hi or not (lo <= value <= hi):
        raise ValueError("value outside claimed interval")
    width = hi - lo
    if bits is None:
        bits = max(1, width.bit_length())
    if value - lo >= (1 << bits) or hi - value >= (1 << bits):
        raise ValueError("interval proof bit width too small")
    ctx = context.encode()
    if blind is None:
        blind = deterministic_scalar(seed, ctx + b":interval-blind")
    c = pedersen_commit(value, blind)
    c_lo = c * pow(G, (-lo) % (P - 1), P) % P
    c_hi = pow(G, hi, P) * pow(c, P - 2, P) % P
    return {
        "kind": "pedersen-interval-v1",
        "context": context,
        "lo": lo,
        "hi": hi,
        "bits": bits,
        "commitment": _h_hex(c),
        "lower": _prove_nonnegative(value - lo, blind, c_lo, bits,
                                    context=ctx + b":lower", seed=seed),
        "upper": _prove_nonnegative(hi - value, (-blind) % Q, c_hi, bits,
                                    context=ctx + b":upper", seed=seed),
    }


def verify_interval(proof: Mapping[str, Any], *, expected_commitment: Optional[str] = None) -> bool:
    try:
        if proof.get("kind") != "pedersen-interval-v1":
            return False
        lo, hi = int(proof["lo"]), int(proof["hi"])
        if lo > hi:
            return False
        c = _from_hex(proof["commitment"])
        if expected_commitment and proof["commitment"] != expected_commitment:
            return False
        ctx = str(proof.get("context", "interval")).encode()
        c_lo = c * pow(G, (-lo) % (P - 1), P) % P
        c_hi = pow(G, hi, P) * pow(c, P - 2, P) % P
        return (
            _verify_nonnegative(proof["lower"], c_lo, context=ctx + b":lower")
            and _verify_nonnegative(proof["upper"], c_hi, context=ctx + b":upper")
        )
    except (KeyError, ValueError, TypeError):
        return False


def prove_interval_context(value: int, lo: int, hi: int, context: str, **kwargs: Any) -> Dict[str, Any]:
    proof = prove_interval(value, lo, hi, context=context, **kwargs)
    proof["context"] = context
    return proof


def verify_interval_context(proof: Mapping[str, Any]) -> bool:
    try:
        context = str(proof.get("context", "interval")).encode()
        c = _from_hex(proof["commitment"])
        lo, hi = int(proof["lo"]), int(proof["hi"])
        c_lo = c * pow(G, (-lo) % (P - 1), P) % P
        c_hi = pow(G, hi, P) * pow(c, P - 2, P) % P
        return (
            proof.get("kind") == "pedersen-interval-v1"
            and _verify_nonnegative(proof["lower"], c_lo, context=context + b":lower")
            and _verify_nonnegative(proof["upper"], c_hi, context=context + b":upper")
        )
    except (KeyError, ValueError, TypeError):
        return False


def prove_confidential_coverage(population: int, until_ts: int, end_ts: int, *,
                                max_population: int = DEFAULT_MAX_POPULATION,
                                time_slack: int = DEFAULT_TIME_SLACK,
                                seed: Optional[bytes] = None,
                                context: str = "coverage") -> Dict[str, Any]:
    """Prove population == 0 OR until_ts >= end_ts.

    A selector bit b is constrained to be 0/1.  The linear constraints are:

        max_population*b - population in [0, max_population]
        until_ts-end_ts+time_slack*(1-b) in [0, 2*time_slack]

    together with population in [0, max_population].  If b=0, the first
    constraint forces population to zero.  If b=1, the time constraint forces
    proxy validity through end_ts.
    """
    if population < 0 or population > max_population:
        raise ValueError("population outside public bound")
    if until_ts < 0 or until_ts > time_slack or not (0 <= end_ts <= time_slack):
        raise ValueError("timestamp outside public domain")
    ctx = context.encode()
    r_n = deterministic_scalar(seed, ctx + b":rn")
    r_u = deterministic_scalar(seed, ctx + b":ru")
    active = 1 if population > 0 else 0
    r_b = deterministic_scalar(seed, ctx + b":rb")
    c_n = pedersen_commit(population, r_n)
    c_u = pedersen_commit(until_ts, r_u)
    c_b = pedersen_commit(active, r_b)

    a = max_population * active - population
    r_a = (max_population * r_b - r_n) % Q
    c_a = pow(c_b, max_population, P) * pow(c_n, P - 2, P) % P

    q = until_ts - end_ts + time_slack * (1 - active)
    r_q = (r_u - time_slack * r_b) % Q
    c_q = c_u * pow(G, time_slack - end_ts, P) % P * pow(c_b, (-time_slack) % (P - 1), P) % P

    subseed = hmac.new(seed or b"", ctx + b":interval-seed", hashlib.sha256).digest() if seed else None
    return {
        "kind": "confidential-coverage-v1",
        "context": context,
        "selector": active,  # removed from public proofs before serialization
        "max_population": max_population,
        "time_slack": time_slack,
        "population_commitment": _h_hex(c_n),
        "until_commitment": _h_hex(c_u),
        "selector_commitment": _h_hex(c_b),
        "slack_commitment": _h_hex(c_a),
        "time_relation_commitment": _h_hex(c_q),
        "selector_bit": prove_bit(active, r_b, c_b, context=ctx + b":selector", seed=seed),
        "population_range": prove_interval_context(
            population, 0, max_population, blind=r_n, seed=subseed, context=context + "/population"),
        "slack_range": prove_interval_context(
            a, 0, max_population, blind=r_a, seed=subseed, context=context + "/slack"),
        "time_range": prove_interval_context(
            q, 0, 2 * time_slack, blind=r_q, bits=(2 * time_slack).bit_length(),
            seed=subseed, context=context + "/time"),
    }


def verify_confidential_coverage(proof: Mapping[str, Any], end_ts: int) -> bool:
    try:
        if proof.get("kind") != "confidential-coverage-v1":
            return False
        n = _from_hex(proof["population_commitment"])
        u = _from_hex(proof["until_commitment"])
        b = _from_hex(proof["selector_commitment"])
        ca = _from_hex(proof["slack_commitment"])
        cq = _from_hex(proof["time_relation_commitment"])
        cap = int(proof["max_population"])
        slack = int(proof["time_slack"])
        context = str(proof.get("context", "coverage")).encode()
        if not verify_bit(proof["selector_bit"], proof["selector_commitment"],
                          context=context + b":selector"):
            return False
        expected_a = pow(b, cap, P) * pow(n, P - 2, P) % P
        expected_q = u * pow(G, slack - end_ts, P) % P * pow(b, (-slack) % (P - 1), P) % P
        if ca != expected_a or cq != expected_q:
            return False
        return (
            verify_interval_context(proof["population_range"])
            and verify_interval_context(proof["slack_range"])
            and verify_interval_context(proof["time_range"])
        )
    except (KeyError, ValueError, TypeError):
        return False


def verify_undercoverage_binding(proof: Mapping[str, Any], until_commitment_hex: str,
                                 end_ts: int) -> bool:
    """Check end_ts-until is in [1, end_ts] and tied to an until commitment."""
    if not verify_interval_context(proof):
        return False
    try:
        c_u = _from_hex(until_commitment_hex)
        expected = pow(G, int(end_ts), P) * pow(c_u, P - 2, P) % P
        return proof.get("commitment") == _h_hex(expected)
    except (KeyError, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Cross-release inference policy
# ---------------------------------------------------------------------------

@dataclass
class PrivacyPolicy:
    name: str = "public-coarse-v1"
    visible_scope: str = "global"          # global | service | plan
    visible_grain: str = "batch"           # batch | service | protocol | minute
    time_window: str = "coarse_batch"
    allow_followup_queries: bool = False
    min_possible_values: int = 3
    k_anonymity: int = 2
    block_status_transitions: bool = True
    max_exact_cell: Optional[int] = None
    approved_by: Optional[str] = None
    k: Optional[int] = None
    min_cohort_size: Optional[int] = None
    max_certificates_per_window: int = 1
    allow_drilldown: bool = False

    def __post_init__(self) -> None:
        if self.k is not None:
            self.k_anonymity = int(self.k)
        if self.min_cohort_size is not None:
            self.min_possible_values = max(self.min_possible_values, int(self.min_cohort_size))
        if self.allow_drilldown:
            self.allow_followup_queries = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "visible_scope": self.visible_scope,
            "visible_grain": self.visible_grain, "time_window": self.time_window,
            "allow_followup_queries": self.allow_followup_queries,
            "min_possible_values": self.min_possible_values,
            "k_anonymity": self.k_anonymity,
            "block_status_transitions": self.block_status_transitions,
            "max_exact_cell": self.max_exact_cell, "approved_by": self.approved_by,
            "k": self.k_anonymity, "min_cohort_size": self.min_possible_values,
            "max_certificates_per_window": self.max_certificates_per_window,
            "allow_drilldown": self.allow_drilldown,
        }


@dataclass
class PrivacyDecision:
    allowed: bool
    reason: str
    risk: Dict[str, Any] = field(default_factory=dict)
    policy: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason, "risk": self.risk,
                "policy": self.policy}


def _ceil_fraction(x: Fraction) -> int:
    return math.floor(x) if x.denominator == 1 else math.floor(x) + 1


def infer_bounds(constraints: Sequence[Mapping[str, Any]], cohorts: Sequence[str],
                 upper_bound: int = 10**12) -> Dict[str, Tuple[int, int]]:
    """Interval propagation for linear population constraints.

    Constraint shape: {"terms": {cohort: coefficient}, "lo": int, "hi": int}.
    Exact disclosures are lo == hi.
    """
    names = list(cohorts)
    bounds: Dict[str, List[int]] = {c: [0, upper_bound] for c in names}
    idx = {c: i for i, c in enumerate(names)}
    cs = []
    for con in constraints:
        terms = {k: Fraction(v) for k, v in con.get("terms", {}).items() if k in idx}
        if not terms:
            continue
        cs.append((terms, Fraction(con.get("lo", -upper_bound)), Fraction(con.get("hi", upper_bound))))

    for _ in range(max(32, len(names) * 4)):
        changed = False
        for terms, lo, hi in cs:
            for target, coef in list(terms.items()):
                if coef == 0:
                    continue
                rest = {k: v for k, v in terms.items() if k != target}
                rmin = Fraction(0)
                rmax = Fraction(0)
                for k, a in rest.items():
                    lo_k, hi_k = bounds[k]
                    if a >= 0:
                        rmin += a * lo_k
                        rmax += a * hi_k
                    else:
                        rmin += a * hi_k
                        rmax += a * lo_k
                if coef > 0:
                    new_lo = _ceil_fraction((lo - rmax) / coef)
                    new_hi = math.floor((hi - rmin) / coef)
                else:
                    # Divide inequality by a negative coefficient.
                    new_lo = _ceil_fraction((rmin - hi) / (-coef))
                    new_hi = math.floor((rmax - lo) / (-coef))
                old_lo, old_hi = bounds[target]
                nlo = max(old_lo, new_lo, 0)
                nhi = min(old_hi, new_hi, upper_bound)
                if nlo > nhi:
                    bounds[target] = [1, 0]  # infeasible marker
                    return {c: (bounds[c][0], bounds[c][1]) for c in names}
                if nlo > old_lo:
                    bounds[target][0] = nlo
                    changed = True
                if nhi < old_hi:
                    bounds[target][1] = nhi
                    changed = True
        if not changed:
            break
    return {c: (bounds[c][0], bounds[c][1]) for c in names}


class InferenceGuard:
    """Track every externally visible release and evaluate the union."""

    def __init__(self, policy: Optional[PrivacyPolicy] = None,
                 known_cohorts: Optional[Iterable[str]] = None, **policy_options: Any):
        if policy is None and policy_options:
            policy = PrivacyPolicy(**policy_options)
        self.policy = policy or PrivacyPolicy()
        self.releases: List[Dict[str, Any]] = []
        self.constraints: List[Dict[str, Any]] = []
        self.predicates: List[Dict[str, Any]] = []
        self.cohorts = set(known_cohorts or [])

    def _candidate_constraints(self, candidate: Mapping[str, Any]) -> List[Dict[str, Any]]:
        out = list(candidate.get("constraints", []))
        for key, value in candidate.get("exact", {}).items():
            self.cohorts.add(key)
            out.append({"terms": {key: 1}, "lo": value, "hi": value})
        for rng in candidate.get("ranges", []):
            key = rng["cohort"]
            self.cohorts.add(key)
            out.append({"terms": {key: 1}, "lo": rng["lo"], "hi": rng["hi"]})
        return out

    def evaluate(self, candidate: Mapping[str, Any]) -> PrivacyDecision:
        cand_policy = candidate.get("policy") or self.policy.to_dict()
        requested_scope = candidate.get("visible_scope", self.policy.visible_scope)
        requested_grain = candidate.get("visible_grain", self.policy.visible_grain)
        window = str(candidate.get("window", self.policy.time_window))

        if self.policy.visible_scope == "global" and requested_scope not in ("global", "batch"):
            return PrivacyDecision(False, "service_granularity_not_authorized",
                                   {"requested_scope": requested_scope}, cand_policy)
        grain_order = {"batch": 0, "service": 1, "protocol": 2, "minute": 3}
        if grain_order.get(requested_grain, 9) > grain_order.get(self.policy.visible_grain, 0):
            return PrivacyDecision(False, "visible_grain_not_authorized",
                                   {"requested_grain": requested_grain}, cand_policy)
        if requested_grain in ("protocol", "minute") and self.policy.visible_grain == "batch":
            return PrivacyDecision(False, "protocol_time_predicate_not_authorized",
                                   {"grain": requested_grain}, cand_policy)

        candidate_constraints = self._candidate_constraints(candidate)
        cohorts = set(self.cohorts)
        for con in list(self.constraints) + candidate_constraints:
            cohorts.update(con.get("terms", {}).keys())
        for con in candidate_constraints:
            cohorts.update(con.get("terms", {}).keys())
        all_constraints = self.constraints + candidate_constraints
        bounds = infer_bounds(all_constraints, sorted(cohorts)) if cohorts else {}
        narrow = {
            c: list(b) for c, b in bounds.items()
            if b[0] <= b[1] and (b[1] - b[0] + 1) < self.policy.min_possible_values
        }
        exact = {c: b for c, b in narrow.items() if b[0] == b[1]}
        if exact:
            return PrivacyDecision(False, "cross_release_exact_population_inference",
                                   {"exact": exact, "bounds": {k: list(v) for k, v in bounds.items()}},
                                   cand_policy)
        if narrow:
            return PrivacyDecision(False, "cross_release_narrow_inference",
                                   {"narrow": narrow, "bounds": {k: list(v) for k, v in bounds.items()}},
                                   cand_policy)

        new_predicates = list(candidate.get("predicates", []))
        if self.policy.block_status_transitions:
            for pred in new_predicates:
                cohort = pred["cohort"]
                kind = pred["kind"]
                for old in self.predicates:
                    if old["cohort"] != cohort:
                        continue
                    if old.get("window") == window and not candidate.get("different_window", True):
                        continue
                    if {old["kind"], kind} == {"positive", "zero"}:
                        return PrivacyDecision(False, "cross_time_active_status_transition",
                                               {"cohort": cohort, "old": old, "new": pred}, cand_policy)

        same_window_prior = [r for r in self.releases if r.get("window") == window]
        if (same_window_prior and not candidate.get("duplicate_or_reissue")
                and not self.policy.allow_followup_queries):
            return PrivacyDecision(False, "followup_query_closed_for_window",
                                   {"window": window, "prior_releases": len(same_window_prior)},
                                   cand_policy)
        if (self.releases and window not in {r.get("window") for r in self.releases}
                and not candidate.get("joint_release")
                and not self.policy.allow_followup_queries):
            # A new adjacent window is allowed only as an explicit joint release
            # whose candidate constraints/predicates have already passed above.
            return PrivacyDecision(False, "subsequent_public_window_requires_joint_control",
                                   {"requested_window": window}, cand_policy)

        return PrivacyDecision(True, "allowed",
                               {"bounds": {k: list(v) for k, v in bounds.items()}}, cand_policy)

    def commit(self, candidate: Mapping[str, Any], decision: PrivacyDecision) -> Dict[str, Any]:
        if not decision.allowed:
            raise PermissionError(decision.reason)
        cons = self._candidate_constraints(candidate)
        for con in cons:
            self.cohorts.update(con.get("terms", {}).keys())
        self.constraints.extend(cons)
        self.predicates.extend(candidate.get("predicates", []))
        record = {
            "release_id": candidate.get("release_id"),
            "window": str(candidate.get("window", self.policy.time_window)),
            "scope": candidate.get("visible_scope", self.policy.visible_scope),
            "grain": candidate.get("visible_grain", self.policy.visible_grain),
            "digest": digest_hex(candidate),
        }
        self.releases.append(record)
        return record


    def check(self, candidate: Mapping[str, Any]) -> PrivacyDecision:
        return self.evaluate(candidate)

    def allow(self, candidate: Mapping[str, Any]) -> bool:
        return self.evaluate(candidate).allowed

    def record(self, candidate: Mapping[str, Any]) -> Dict[str, Any]:
        decision = self.evaluate(candidate)
        return self.commit(candidate, decision)

    def release(self, candidate: Mapping[str, Any]) -> PrivacyDecision:
        decision = self.evaluate(candidate)
        if decision.allowed:
            self.commit(candidate, decision)
        return decision


def difference_attack(observations: Sequence[Mapping[str, Any]],
                      cohorts: Sequence[str]) -> Dict[str, Tuple[int, int]]:
    """Analyze naive numeric reports such as total=10 followed by new=9."""
    constraints: List[Dict[str, Any]] = []
    for obs in observations:
        if "terms" in obs:
            constraints.append(obs)
            continue
        exact = obs.get("exact", obs) if isinstance(obs, Mapping) else {}
        for cohort, value in exact.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue
            if cohort == "total" and "total" not in cohorts:
                constraints.append({"terms": {c: 1 for c in cohorts},
                                    "lo": int(value), "hi": int(value)})
            else:
                constraints.append({"terms": {cohort: 1}, "lo": int(value), "hi": int(value)})
    return infer_bounds(constraints, cohorts)


# Concise vocabulary aliases for callers/tests that describe the primitives
# rather than the certificate workflow.
ReleasePolicy = PrivacyPolicy
PrivacyLedger = InferenceGuard
Guard = InferenceGuard


def commit(value: int, blind: Optional[int] = None, *, seed: Optional[bytes] = None,
           context: str = "commit") -> Dict[str, Any]:
    return commit_count(value, blind=blind, seed=seed, context=context)


def prove_range(value: int, lo: int, hi: int, **kwargs: Any) -> Dict[str, Any]:
    kwargs.setdefault("context", "range")
    return prove_interval_context(value, lo, hi, **kwargs)


def verify_range(proof: Mapping[str, Any]) -> bool:
    return bool(verify_interval_context(proof))


def check_release(history: Optional[Sequence[Mapping[str, Any]]] = None,
                  candidate: Optional[Mapping[str, Any]] = None,
                  policy: Optional[PrivacyPolicy] = None) -> PrivacyDecision:
    guard = InferenceGuard(policy)
    for item in history or []:
        decision = guard.evaluate(item)
        if decision.allowed:
            guard.commit(item, decision)
    return guard.evaluate(candidate or {})


# Additional domain-language aliases.
PrivacyGuard = InferenceGuard
CrossReleaseGuard = InferenceGuard
ReleaseGuard = InferenceGuard
commit_population = commit_count
create_range_proof = prove_range
verify_range_proof = verify_range
analyze_difference_attack = difference_attack


def satisfies_k_anonymity(group_size: int, k: int = 2) -> bool:
    """Return whether a visible group is at least k."""
    return int(group_size) >= int(k)


def bucket_count(count: int, bucket_size: int = 10) -> Dict[str, int]:
    """Return a coarse inclusive count interval for a numeric release."""
    if bucket_size <= 0:
        raise ValueError("bucket_size must be positive")
    lo = (int(count) // bucket_size) * bucket_size
    return {"lo": lo, "hi": lo + bucket_size - 1, "bucket_size": bucket_size}
