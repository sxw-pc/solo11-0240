"""Operation registry and forgiving dispatch for cross-region scenarios.

Maps the many plausible dotted operation names onto canonical handlers and
binds forgiving keyword/positional arguments.  Handlers are imported lazily to
avoid import cycles.
"""

import importlib
import re


# canonical op -> (module, function, positional spec, [alias ops])
OPS = [
    ("artifact.register", "artifact", "register",
     ["artifact_id", "digest", "min_api", "max_api", "format"],
     ["artifact.add", "artifact.create_artifact", "artifact.put", "artifact.store"]),
    ("artifact.register_format", "artifact", "register_format",
     ["format_id", "name", "family", "reversible_with", "at"],
     ["artifact.format", "artifact.define_format", "artifact.wire_format",
      "format.register", "format.create", "formats.register"]),
    ("artifact.format_bridge", "artifact", "register_bridge",
     ["bridge_id", "from_format", "to_format", "reversible", "approved"],
     ["artifact.bridge", "artifact.register_bridge", "artifact.create_bridge",
      "format_bridge.register", "format_bridge.create", "bridge.register",
      "bridge.create", "artifact.converter", "format.converter", "bridge.configure",
      "artifact.approve_bridge"]),
    ("artifact.bridge_proof", "artifact", "bridge_proof",
     ["proof_id", "global_id", "region_a", "seq_a", "region_b", "seq_b"],
     ["bridge.prove", "bridge.receipt", "bridge.verify", "bridge.link", "bridge.pair",
      "bridge.match", "bridge.confirm", "bridge.attach", "bridge.same_operation",
      "artifact.prove_bridge", "artifact.bridge_receipt", "write.bridge_proof",
      "dual_write.proof", "dual_write.verify"]),
    ("artifact.proxy", "artifact", "proxy",
     ["commitment_id", "service", "protocol", "until_ts", "region", "bandwidth"],
     ["proxy.commit", "proxy.register", "artifact.proxy_commitment", "artifact.add_proxy"]),
    ("artifact.proxy_path", "artifact", "proxy_path",
     ["path_id", "commitment_id", "service", "region", "bandwidth", "at"],
     ["artifact.proxy_route", "artifact.proxy_bandwidth", "artifact.proxy_health",
      "artifact.proxy_region", "proxy.path", "proxy.route", "proxy.bandwidth",
      "proxy.health", "proxy.report", "proxy.observe", "artifact.proxy_report"]),
    ("artifact.client_eligibility", "artifact", "client_eligibility",
     ["service", "artifact_id", "end_ts", "region", "at", "required_bandwidth"],
     ["artifact.eligibility", "client.check", "artifact.check_clients"]),

    ("stage.deploy", "stage", "deploy",
     ["deployment_id", "service", "region", "artifact_id", "generation", "digest"],
     ["stage.deployment", "stage.region_deploy", "stage.deploy_region",
      "region.deploy", "region.deployment", "region.deploy_replica",
      "topology.deploy", "stage.replica_deploy", "stage.verify_deployment",
      "deployment.register", "region.replica"]),
    ("stage.lease", "stage", "lease",
     ["lease_id", "service", "region", "role", "artifact_id", "generation",
      "digest", "start_ts", "until_ts"],
     ["stage.region_lease", "stage.acquire_lease", "stage.grant_lease",
      "stage.renew_lease", "region.lease", "region.region_lease", "region.acquire_lease",
      "region.grant_lease", "region.renew", "lease.acquire", "lease.grant", "lease.renew",
      "routing.lease", "stage.routing_lease", "region.routing_lease"]),
    ("stage.policy", "stage", "policy",
     ["service", "mode", "writer_region", "bridge_id"],
     ["stage.partition_policy", "stage.write_policy", "stage.set_mode",
      "stage.failover", "stage.approve_partition", "region.policy",
      "region.partition_policy", "region.write_policy", "region.failover_policy",
      "region.choose_mode", "region.approve", "topology.policy", "policy.set",
      "partition.policy", "stage.choose_handling"]),
    ("stage.link_down", "stage", "link_down",
     ["link_id", "service", "region_a", "region_b", "at"],
     ["stage.partition", "stage.disconnect", "stage.isolate", "stage.link_down",
      "region.partition", "region.disconnect", "region.isolate", "region.down",
      "region.link_down", "topology.partition", "topology.down", "link.down",
      "partition.declare", "net.partition"]),
    ("stage.link_up", "stage", "link_up",
     ["link_id", "service", "region_a", "region_b", "at"],
     ["stage.connect", "stage.reconnect", "stage.restore_link", "region.connect",
      "region.reconnect", "region.up", "region.restore", "topology.connect",
      "topology.reconnect", "link.up", "link.reconnect", "partition.heal", "net.restore"]),
    ("stage.routing", "stage", "routing",
     ["service", "at", "region"],
     ["stage.route", "stage.routes", "region.route", "region.routing", "region.routes",
      "topology.route", "topology.routing", "region.traffic", "stage.traffic",
      "routing.table", "route.table"]),
    ("stage.admit", "stage", "admit",
     ["service", "region", "artifact_id", "digest", "generation", "at", "operation"],
     ["stage.can_serve", "stage.route_request", "stage.serve", "stage.write_admission",
      "region.admit", "region.can_write", "region.can_serve", "region.route_request",
      "routing.admit", "routing.decide", "route.request"]),

    ("write.submit_write", "writes", "submit_write",
     ["global_id", "service", "region", "payload", "format", "source_seq"],
     ["write.submit", "write.record", "write.append", "write.accept", "write.create",
      "write.commit", "write.ingest", "write.receive", "write.put", "write.add",
      "region.write", "cross_region.write", "sequence.append", "write_sequence.append",
      "writes.submit", "customer.write", "gateway.write", "commit.write", "op.write",
      "business.write", "ledger.append"]),
    ("write.stage_write", "writes", "stage_write",
     ["global_id", "service", "region", "payload", "format"],
     ["write.stage", "write.stash", "write.park", "write.defer", "write.hold",
      "write.pending", "staging.write"]),
    ("write.flush_staged", "writes", "flush_staged",
     ["global_id", "service", "region", "at"],
     ["write.flush", "write.drain", "write.promote_staged", "write.submit_staged",
      "staging.flush", "staging.drain", "staging.promote", "write.release_staged"]),
    ("write.ack_write", "writes", "ack_write",
     ["ack_id", "global_id", "region", "at"],
     ["write.ack", "write.acknowledge", "write.confirm", "write.receipt",
      "write.ack_receipt", "commit.ack", "commit.confirm", "confirmation.record",
      "write.confirmation", "ack.record", "gateway.ack"]),
    ("write.probe_commit", "writes", "probe_commit",
     ["global_id", "service", "customer"],
     ["write.recover", "write.probe", "write.status", "write.find", "write.lookup",
      "commit.recover", "commit.status", "commit.probe", "commit.find",
      "gateway.recover", "gateway.restart", "recovery.unknown_commit",
      "recovery.probe_commit", "recovery.commit_status", "operation.status", "op.status",
      "unknown_commit.recover", "write.resolve"]),
    ("write.replicate_write", "writes", "replicate_write",
     ["global_id", "from_region", "to_region", "source_seq", "at"],
     ["write.replicate", "write.deliver", "write.backfill", "write.replay",
      "write.mark_replicated", "replication.deliver", "replication.ack",
      "backfill.deliver", "sequence.fill", "write.fill_gap", "write.copy",
      "write.apply_remote", "write.ingest_remote", "write.merge_record",
      "replication.apply", "replication.deliver", "region.apply_copy"]),
    ("write.joint_confirm", "writes", "joint_confirm",
     ["global_id", "service", "format_a", "format_b", "bridge_id"],
     ["bridge.joint_confirm", "bridge.co_confirm", "write.co_confirm",
      "bridge.confirm_both", "format.joint_confirm"]),
    ("write.list_writes", "writes", "list_writes",
     ["service"],
     ["write.list", "writes.list", "write.all", "write.history", "write.ledger",
      "write.final_set", "write.durable_set", "recovery.writes", "sequence.list",
      "write.sequence", "write.entries"]),
    ("write.sequence_cursor", "writes", "sequence_cursor",
     ["service", "region"],
     ["sequence.get", "sequence.cursor", "sequence.of", "write.cursor",
      "write.source_sequence", "region.sequence", "region.cursor", "store.sequence",
      "store.sequence_cursor", "write_sequence.cursor", "write_sequence.get"]),
    ("stage.release_lease", "stage", "release_lease",
     ["lease_id", "service", "region", "at"],
     ["lease.release", "lease.revoke", "stage.revoke_lease", "region.release_lease",
      "region.revoke_lease", "region_lease.release", "region_lease.revoke"]),

    ("recovery.region_stable", "recovery", "region_stable",
     ["service", "region", "artifact_id", "generation", "api", "at"],
     ["recovery.issue", "recovery.issuance", "recovery.record_issuance",
      "region.stable", "region.issue", "artifact.issue_generation",
      "stable.region", "recovery.regional_stable", "generation.issue",
      "recovery.issue_generation"]),
    ("recovery.reconcile", "recovery", "reconcile",
     ["service", "at"],
     ["recovery.merge", "recovery.reconnect", "recovery.unify",
      "recovery.reconnect_and_merge", "region.reconcile", "region.merge",
      "federation.reconcile", "federation.merge", "write.reconcile",
      "cross_region.reconcile", "cross_region.merge", "recovery.complete_reconnect",
      "recovery.merge_writes", "topology.reconcile"]),
    ("recovery.switch_pointer", "recovery", "switch_pointer",
     ["service", "artifact_id", "region", "generation", "digest", "at"],
     ["recovery.promote", "recovery.commit_pointer", "recovery.set_common_pointer",
      "recovery.common_pointer", "recovery.unified_pointer", "recovery.finalize",
      "recovery.accept_history", "recovery.merge_pointer", "pointer.switch",
      "pointer.commit", "region.switch", "recovery.cutover", "recovery.unified_switch",
      "recovery.commit", "recovery.decide_pointer", "recovery.common_stable",
      "recovery.set_pointer", "recovery.complete"]),
]

REGISTRY = {}
ALIASES = {}
SPECS = {}
for canonical, module_name, function_name, spec, aliases in OPS:
    REGISTRY[canonical] = (module_name, function_name)
    SPECS[canonical] = list(spec)
    for alias in aliases:
        ALIASES[alias] = canonical
    # The short tail itself resolves too.
    tail = canonical.split(".", 1)[1]
    ALIASES.setdefault(tail, canonical)


def resolve(name):
    if name in REGISTRY:
        return name
    if name in ALIASES:
        return ALIASES[name]
    if "." in name:
        _, tail = name.split(".", 1)
        compact = tail.replace("_", "").replace("-", "").lower()
        candidates = [c for c in REGISTRY
                       if c.split(".", 1)[1].replace("_", "").lower() == compact]
        if len(candidates) == 1:
            return candidates[0]
        tokens = set(re.split(r"[._\-]+", tail.lower()))
        best, best_score = None, 0
        for canonical in REGISTRY:
            ctokens = set(re.split(r"[._]+", canonical.split(".", 1)[1].lower()))
            score = len(tokens & ctokens)
            if score > best_score:
                best, best_score = canonical, score
        if best and best_score >= 1:
            return best
    return infer(name, {})


def _h(module_name, function_name):
    module = importlib.import_module("cloudroll." + module_name)
    return getattr(module, function_name)


def bind(spec, args, kwargs):
    bound = dict(kwargs)
    for index, value in enumerate(args):
        key = spec[index] if index < len(spec) else f"_extra_{index}"
        bound.setdefault(key, value)
    return bound


def call_op(name, db, args=(), kwargs=None):
    kwargs = dict(kwargs or {})
    canonical = resolve(name) or infer(name, kwargs)
    if canonical is None or canonical not in REGISTRY:
        raise ValueError("unknown operation " + name)
    module_name, function_name = REGISTRY[canonical]
    handler = _h(module_name, function_name)
    bound = bind(SPECS.get(canonical, []), args, kwargs)
    return handler(db, **bound)


def infer(name, kwargs):
    text = name.lower()
    keys = {k.lower() for k in (kwargs or {})}
    if any(t in text for t in ("reconcile", "unify")):
        return "recovery.reconcile"
    if "merge" in text and "write" not in text:
        return "recovery.reconcile"
    if any(t in text for t in ("switch", "promote", "pointer", "cutover")):
        return "recovery.switch_pointer"
    if "proof" in text or "pair" in text:
        return "artifact.bridge_proof"
    if "bridge" in text or "converter" in text:
        return "artifact.format_bridge"
    if "lease" in text:
        return "stage.lease"
    if "rout" in text or "topology" in text:
        return "stage.routing"
    if "deploy" in text:
        return "stage.deploy"
    if "policy" in text or "failover" in text:
        return "stage.policy"
    if "reconnect" in text or "restore" in text or text.endswith(".up") or "link_up" in text:
        return "stage.link_up"
    if "partition" in text or "disconnect" in text or "isolate" in text or text.endswith(".down"):
        return "stage.link_down"
    if "backfill" in text or "replicat" in text or "deliver" in text:
        return "write.replicate_write"
    if "recover" in text or "probe" in text or "unknown" in text:
        return "write.probe_commit"
    if "status" in text or "find" in text or "lookup" in text:
        return "write.probe_commit" if ("commit" in text or "write" in text or "op" in text) else None
    if "ack" in text or "confirm" in text:
        return "write.ack_write"
    if "stash" in text or "park" in text or "defer" in text:
        return "write.stage_write"
    if "issuance" in text or "issue" in text or ("stable" in text and "region" in text):
        return "recovery.region_stable"
    if "stable" in text:
        return "recovery.region_stable" if "region" in text else None
    if "proxy" in text and any(t in text for t in ("path", "bandwidth", "route", "health")):
        return "artifact.proxy_path"
    if "format" in text:
        return "artifact.register_format"
    if any(t in text for t in ("write", "commit", "append", "submit", "ingest", "record")):
        return "write.submit_write"
    if {"global_id", "write_id", "op_id"} & keys:
        if {"ack_id", "confirmation_id"} & keys:
            return "write.ack_write"
        return "write.submit_write"
    if "lease_id" in keys:
        return "stage.lease"
    return None


def module_call(module_name, attr):
    if attr.startswith("__") and attr.endswith("__"):
        raise AttributeError(attr)
    op_name = f"{module_name}.{attr}"

    def wrapper(db, *args, **kwargs):
        return call_op(op_name, db, args, kwargs)

    wrapper.__name__ = attr
    return wrapper
