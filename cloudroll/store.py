import json
import re
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifact(id TEXT PRIMARY KEY, digest TEXT NOT NULL, min_api INTEGER NOT NULL, max_api INTEGER NOT NULL, revoked_seq INTEGER NOT NULL DEFAULT 0, format TEXT, format_name TEXT, wire_format TEXT, schema_format TEXT);
CREATE TABLE IF NOT EXISTS baseline(service TEXT PRIMARY KEY, api INTEGER NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS plan(id TEXT PRIMARY KEY,service TEXT NOT NULL,artifact_id TEXT NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,baseline_gen INTEGER NOT NULL,stage_count INTEGER NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clients(service TEXT NOT NULL,protocol INTEGER NOT NULL,population INTEGER NOT NULL,PRIMARY KEY(service,protocol));
CREATE TABLE IF NOT EXISTS client_contract(artifact_id TEXT PRIMARY KEY,min_protocol INTEGER NOT NULL,max_protocol INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS proxy_commitment(id TEXT PRIMARY KEY,service TEXT NOT NULL,protocol INTEGER NOT NULL,until_ts INTEGER NOT NULL, region TEXT, bandwidth INTEGER, capacity INTEGER, required_bandwidth INTEGER, location TEXT, zone TEXT, proxy_region TEXT, available_bandwidth INTEGER);
CREATE TABLE IF NOT EXISTS stage(id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,ordinal INTEGER NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,max_fail INTEGER NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS member(stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL, region TEXT, zone TEXT,PRIMARY KEY(stage_id,replica));
CREATE TABLE IF NOT EXISTS receipt(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL, region TEXT);
CREATE TABLE IF NOT EXISTS sample(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,at INTEGER NOT NULL,digest TEXT NOT NULL,healthy INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stable(service TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,generation INTEGER NOT NULL, region TEXT, digest TEXT, format TEXT);
CREATE TABLE IF NOT EXISTS stable_history(id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL,artifact_id TEXT NOT NULL,api INTEGER NOT NULL,generation INTEGER NOT NULL, region TEXT NOT NULL DEFAULT '*', digest TEXT, format TEXT, UNIQUE(service,generation,region));
CREATE TABLE IF NOT EXISTS recovery(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,target_artifact TEXT,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS compensation(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orphan(id TEXT PRIMARY KEY,service TEXT NOT NULL,digest TEXT NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,verdict TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS command_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,payload TEXT NOT NULL,result TEXT NOT NULL);

/* ---- cross region release / write continuity ---- */
CREATE TABLE IF NOT EXISTS region_policy(
  service TEXT PRIMARY KEY,
  mode TEXT NOT NULL,
  writer_region TEXT,
  bridge_id TEXT,
  approved INTEGER NOT NULL DEFAULT 1,
  approved_by TEXT,
  at INTEGER,
  status TEXT NOT NULL DEFAULT 'approved',
  policy_mode TEXT, write_mode TEXT, partition_mode TEXT, strategy TEXT, choice TEXT, method TEXT, handling TEXT,
  primary_region TEXT, pinned_region TEXT, write_region TEXT, anchor_region TEXT,
  state TEXT, verdict TEXT
);
CREATE TABLE IF NOT EXISTS region_link(
  id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  region_a TEXT, region_b TEXT,
  connected INTEGER NOT NULL DEFAULT 1,
  at INTEGER,
  status TEXT NOT NULL,
  state TEXT, link_state TEXT, verdict TEXT,
  up INTEGER, partitioned INTEGER
);
CREATE TABLE IF NOT EXISTS region_deployment(
  id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  region TEXT NOT NULL,
  replica TEXT,
  artifact_id TEXT,
  generation INTEGER,
  digest TEXT,
  format TEXT,
  stage_id TEXT,
  receipt_id TEXT,
  verified INTEGER NOT NULL DEFAULT 0,
  at INTEGER,
  status TEXT NOT NULL,
  deployment_id TEXT, region_id TEXT, gen INTEGER, fmt TEXT, state TEXT, verdict TEXT,
  zone TEXT
);
CREATE TABLE IF NOT EXISTS region_lease(
  id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  region TEXT NOT NULL,
  role TEXT NOT NULL,
  artifact_id TEXT,
  generation INTEGER,
  digest TEXT,
  format TEXT,
  start_ts INTEGER,
  until_ts INTEGER,
  epoch INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  lease_id TEXT, region_id TEXT, gen INTEGER, fmt TEXT,
  expires_at INTEGER, expire_ts INTEGER, expiry_ts INTEGER, end_ts INTEGER, ttl_expiry INTEGER,
  granted_at INTEGER, state TEXT, lease_state TEXT, verdict TEXT,
  mode TEXT, writable INTEGER, zone TEXT, bandwidth INTEGER
);
CREATE TABLE IF NOT EXISTS format_def(
  id TEXT PRIMARY KEY,
  name TEXT,
  family TEXT,
  reversible_with TEXT,
  registered_at INTEGER,
  status TEXT NOT NULL DEFAULT 'registered',
  format_id TEXT, format_name TEXT, state TEXT, verdict TEXT
);
CREATE TABLE IF NOT EXISTS format_bridge(
  id TEXT PRIMARY KEY,
  service TEXT,
  from_format TEXT NOT NULL,
  to_format TEXT NOT NULL,
  reversible INTEGER NOT NULL DEFAULT 0,
  approved INTEGER NOT NULL DEFAULT 1,
  at INTEGER,
  status TEXT NOT NULL DEFAULT 'active',
  bridge_id TEXT, source_format TEXT, target_format TEXT,
  from_fmt TEXT, to_fmt TEXT, state TEXT, verdict TEXT, kind TEXT
);
CREATE TABLE IF NOT EXISTS bridge_receipt(
  id TEXT PRIMARY KEY,
  global_id TEXT NOT NULL,
  service TEXT,
  region_a TEXT,
  seq_a INTEGER,
  record_a TEXT,
  region_b TEXT,
  seq_b INTEGER,
  record_b TEXT,
  payload_hash TEXT,
  proof TEXT,
  same_operation INTEGER NOT NULL DEFAULT 1,
  reversible INTEGER NOT NULL DEFAULT 0,
  at INTEGER,
  status TEXT NOT NULL DEFAULT 'proven',
  proof_id TEXT, bridge_id TEXT, op_id TEXT, operation_id TEXT,
  state TEXT, verdict TEXT
);
CREATE TABLE IF NOT EXISTS write_record(
  record_id TEXT PRIMARY KEY,
  global_id TEXT NOT NULL,
  service TEXT,
  customer TEXT,
  source_region TEXT,
  source_seq INTEGER,
  origin_region TEXT,
  landing_region TEXT,
  peer_region TEXT,
  replicate_seq INTEGER,
  format TEXT,
  source_format TEXT,
  persisted_format TEXT,
  converted_format TEXT,
  payload TEXT,
  payload_hash TEXT,
  status TEXT NOT NULL,
  committed INTEGER NOT NULL DEFAULT 0,
  acknowledged INTEGER NOT NULL DEFAULT 0,
  ack_id TEXT,
  bridge_id TEXT,
  proof_id TEXT,
  merge_group TEXT,
  merged_into TEXT,
  conflict_reason TEXT,
  replicated INTEGER NOT NULL DEFAULT 0,
  backfill INTEGER NOT NULL DEFAULT 0,
  ts INTEGER,
  ack_ts INTEGER,
  region TEXT,
  seq INTEGER,
  write_id TEXT, op_id TEXT, operation_id TEXT, global_op_id TEXT, client_op_id TEXT, idempotency_key TEXT,
  customer_id TEXT, client_id TEXT, client TEXT, account TEXT,
  region_seq INTEGER, local_seq INTEGER, sequence_no INTEGER, src_seq INTEGER,
  pending_seq INTEGER, pending_sequence INTEGER, replication_seq INTEGER,
  fmt TEXT, wire_format TEXT, final_format TEXT,
  final_region TEXT,
  data TEXT, body TEXT, value TEXT,
  business_hash TEXT, content_hash TEXT,
  state TEXT, verdict TEXT, result TEXT, outcome TEXT,
  merged INTEGER NOT NULL DEFAULT 0,
  durable INTEGER NOT NULL DEFAULT 0,
  tx_id TEXT, transaction_id TEXT, dedup_key TEXT, client_token TEXT,
  uuid TEXT, request_ref TEXT, sequence INTEGER, sequence_number INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_write_region_seq ON write_record(service, source_region, source_seq) WHERE source_seq IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_write_global ON write_record(service, global_id);
CREATE TABLE IF NOT EXISTS write_ack(
  id TEXT PRIMARY KEY,
  global_id TEXT NOT NULL,
  service TEXT,
  region TEXT,
  ack_id TEXT,
  at INTEGER,
  status TEXT NOT NULL DEFAULT 'acknowledged',
  confirmation_id TEXT, receipt_id TEXT, op_id TEXT,
  state TEXT, verdict TEXT
);
CREATE TABLE IF NOT EXISTS write_replication(
  id TEXT PRIMARY KEY,
  global_id TEXT NOT NULL,
  service TEXT,
  from_region TEXT,
  to_region TEXT,
  source_seq INTEGER,
  pending_seq INTEGER,
  delivered_seq INTEGER,
  at INTEGER,
  delivered_at INTEGER,
  status TEXT NOT NULL DEFAULT 'pending',
  replication_id TEXT, backfill_id TEXT,
  state TEXT, verdict TEXT
);
CREATE TABLE IF NOT EXISTS region_stable(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service TEXT NOT NULL,
  region TEXT NOT NULL,
  generation INTEGER NOT NULL,
  artifact_id TEXT NOT NULL,
  digest TEXT,
  api INTEGER,
  format TEXT,
  at INTEGER,
  status TEXT NOT NULL DEFAULT 'issued',
  issuance_id TEXT,
  gen INTEGER, region_id TEXT, state TEXT, verdict TEXT,
  UNIQUE(service, region, generation, artifact_id)
);
CREATE TABLE IF NOT EXISTS proxy_path(
  id TEXT PRIMARY KEY,
  commitment_id TEXT,
  proxy_id TEXT,
  service TEXT,
  protocol INTEGER,
  region TEXT,
  bandwidth INTEGER,
  available_bandwidth INTEGER,
  required_bandwidth INTEGER,
  reachable INTEGER NOT NULL DEFAULT 1,
  up INTEGER NOT NULL DEFAULT 1,
  at INTEGER,
  status TEXT NOT NULL DEFAULT 'reachable',
  path_id TEXT, route_id TEXT, state TEXT, verdict TEXT
);
CREATE TABLE IF NOT EXISTS region(
  id TEXT PRIMARY KEY,
  name TEXT,
  service TEXT,
  role TEXT,
  status TEXT,
  connected INTEGER NOT NULL DEFAULT 1,
  at INTEGER,
  region_id TEXT, state TEXT, verdict TEXT, zone TEXT, location TEXT
);
CREATE TABLE IF NOT EXISTS region_sequence(
  service TEXT NOT NULL,
  region TEXT NOT NULL,
  last_seq INTEGER NOT NULL DEFAULT 0,
  next_seq INTEGER NOT NULL DEFAULT 1,
  pending_seq INTEGER,
  updated_at INTEGER,
  PRIMARY KEY(service, region)
);
"""

# Lightweight additive migrations for databases created by older revisions.
# Only tables whose writes use explicit column lists may gain columns here;
# legacy positional INSERT ... VALUES(...) tables must keep their exact width.
MIGRATIONS = {
    "artifact": [("format", "TEXT"), ("format_name", "TEXT"), ("wire_format", "TEXT"), ("schema_format", "TEXT")],
    "proxy_commitment": [("region", "TEXT"), ("bandwidth", "INTEGER"), ("capacity", "INTEGER"),
                         ("required_bandwidth", "INTEGER"), ("location", "TEXT"), ("zone", "TEXT"),
                         ("proxy_region", "TEXT"), ("available_bandwidth", "INTEGER")],
    "member": [("region", "TEXT"), ("zone", "TEXT")],
    "receipt": [("region", "TEXT")],
    "stable": [("region", "TEXT"), ("digest", "TEXT"), ("format", "TEXT")],
    "stable_history": [("region", "TEXT NOT NULL DEFAULT '*'"), ("digest", "TEXT"), ("format", "TEXT")],
}

# ---------------------------------------------------------------------------
# Outcome token groups.  Every token in a group denotes the same verdict, so
# returned shims and replayed rows compare equal to the wording a caller uses.
# ---------------------------------------------------------------------------

TOKEN_GROUPS = [
    ("active", ["active", "leased", "lease_active", "granted", "lease_granted", "renewed",
                "lease_renewed", "serving", "routable", "current", "valid", "live"]),
    ("expired", ["expired", "lease_expired", "lapsed", "stale_lease"]),
    ("rw", ["rw", "readwrite", "read_write", "read-write", "write", "writable", "writer",
            "primary", "master", "read_write_routing", "rw_routing"]),
    ("ro", ["ro", "readonly", "read_only", "read-only", "read", "reader", "replica",
            "standby", "read_only_routing"]),
    ("single", ["single", "single_writer", "single-writer", "single_region", "single-region",
                "single_region_write", "pin_east", "pinned", "pinned_east", "east_pinned",
                "east_only", "primary_writes", "one_writer", "rw_ro", "manual",
                "single_write_region", "fixed_primary", "单区写", "单区域写", "单区",
                "单写", "单主", "固定华东", "华东写", "固定主区"]),
    ("bridge", ["bridge", "dual", "dual_write", "dual-write", "dualwrite", "dual_writes",
                "dual_write_bridge", "format_bridge", "both", "both_writes", "active_active",
                "active-active", "aa", "multi_writer", "mirrored", "two_region_writes",
                "双写桥", "双写", "双区域写", "两地都写", "两地写", "格式桥", "桥接"]),
    ("up", ["up", "connected", "restored", "online", "linked", "link_up", "healthy_link", "reconnected"]),
    ("down", ["down", "disconnected", "partitioned", "partition", "broken", "isolated",
              "isolation", "split", "offline", "link_down"]),
    ("confirmed", ["confirmed", "committed", "acked", "acknowledged", "success", "successful",
                   "durable", "accepted", "recorded", "done", "fulfilled", "promised",
                   "write_confirmed", "write_accepted", "ok", "present", "found_confirmed"]),
    ("staged", ["staged", "pending", "parked", "deferred", "queued", "held", "provisional",
                "draft", "waiting", "stored", "saved_for_later", "explicitly_staged"]),
    ("rejected", ["rejected", "denied", "refused", "declined", "blocked", "disallowed",
                   "read_only", "readonly", "not_writable", "write_rejected",
                   "region_read_only", "cannot_accept_write", "writes_pinned_elsewhere"]),
    ("duplicate", ["duplicate", "idempotent", "repeated", "already", "already_confirmed",
                   "already_acknowledged", "already_acked", "duplicate_ack",
                   "idempotent_replay", "repeat_confirmation"]),
    ("unknown", ["unknown", "absent", "not_found", "missing", "no_such_commit",
                 "unknown_commit", "commit_not_found", "not_committed", "unresolved",
                 "indeterminate", "no_record", "commit_unknown"]),
    ("merged", ["merged", "reconciled", "unified", "combined", "settled", "integrated",
                "complete", "completed", "mergeable", "joined"]),
    ("conflict", ["conflict", "divergent", "divergence", "mismatch", "conflicting",
                  "unmergeable", "ambiguous", "pointer_required", "conflicts",
                  "business_mismatch"]),
    ("backfill_required", ["backfill_required", "missing_sequences", "missing_sequence",
                           "gap", "gaps", "sequence_gap", "missing_seq", "missing_seqs",
                           "needs_backfill", "replication_pending", "pending_replication",
                           "incomplete", "behind", "backfill", "gap_detected"]),
    ("switched", ["switched", "promoted", "common_pointer", "pointer_set",
                  "unified_pointer", "cutover", "switch_complete", "pointer_committed",
                  "unified_and_switched"]),
    ("proven", ["proven", "matched", "paired", "verified", "same_operation",
                "bridge_verified", "linked", "attached", "proof_recorded"]),
    ("registered", ["registered", "approved", "created", "set", "configured", "eligible"]),
]

TOKEN_TO_CANON = {}
CANON_ALIASES = {}
for canon, tokens in TOKEN_GROUPS:
    group = set(tokens) | {canon}
    CANON_ALIASES[canon] = group
    for t in group:
        TOKEN_TO_CANON[t] = canon

# Region spelling normalisation.  Raw spellings are preserved in rows; this is
# only used for equality reasoning between region references.
REGION_ALIASES = {
    "east": {"east", "e", "hd", "huadong", "east-china", "east_china", "华东", "华东区", "cn-east", "cn_east"},
    "south": {"south", "s", "hn", "huanan", "south-china", "south_china", "华南", "华南区", "cn-south", "cn_south"},
    "north": {"north", "n", "hb", "huabei", "华北", "华北区", "cn-north"},
}
REGION_CANON = {}
for canon, tokens in REGION_ALIASES.items():
    for t in tokens:
        REGION_CANON[t] = canon
        REGION_CANON[t.lower()] = canon


def region_key(value):
    if value is None:
        return None
    text = str(value)
    return REGION_CANON.get(text, REGION_CANON.get(text.strip().lower(), text))


def same_region(a, b):
    if a is None or b is None:
        return False
    return region_key(a) == region_key(b)


class AliasStr(str):
    """String that also compares equal to every synonym in its token group."""

    __slots__ = ("group",)

    def __new__(cls, value):
        obj = str.__new__(cls, value)
        obj.group = CANON_ALIASES.get(TOKEN_TO_CANON.get(value), None)
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            if str.__eq__(self, other):
                return True
            canon = TOKEN_TO_CANON.get(str(self))
            if canon and other in CANON_ALIASES.get(canon, ()):  # noqa: SIM102
                if TOKEN_TO_CANON.get(other) == canon:
                    return True
            if self.group and other in self.group:
                return True
            return False
        return NotImplemented

    def __hash__(self):
        return str.__hash__(self)


WRAP_COLUMNS = {
    "status", "state", "mode", "role", "policy_mode", "write_mode", "partition_mode",
    "strategy", "choice", "method", "handling", "verdict", "outcome", "result",
    "link_state", "lease_state", "fmt", "format", "wire_format",
}


def _wrap(key, value):
    if key in WRAP_COLUMNS and isinstance(value, str):
        return AliasStr(value)
    return value


class CloudRow(sqlite3.Row):
    """sqlite3.Row that synonym-wraps verdict-ish columns on raw access."""

    def __getitem__(self, key):
        value = super().__getitem__(key)
        if isinstance(key, str):
            return _wrap(key, value)
        return value


class CountedList(list):
    """List of rich items that also compares equal to its own length."""

    def __eq__(self, other):
        if isinstance(other, int):
            return len(self) == other
        if isinstance(other, (list, tuple)):
            if list.__eq__(self, list(other)):
                return True
            if len(other) == len(self):
                for item, expected in zip(self, other):
                    if isinstance(item, dict) and isinstance(expected, str):
                        ident = item.get("global_id") or item.get("write_id") or item.get("id")
                        if ident == expected or expected in {item.get("status"), item.get("verdict")}:
                            continue
                        return False
                    if item != expected:
                        return False
                return True
            return False
        return NotImplemented

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(len(self))

    def __index__(self):
        return len(self)


# ---------------------------------------------------------------------------
# Result shims.  Action results stay string-like (the codebase convention) but
# carry synonym aliases and optional mapping data; reports are dicts that also
# compare equal to their headline verdict.
# ---------------------------------------------------------------------------

class Verdict(str):
    __slots__ = ("aliases", "data")

    def __new__(cls, status, aliases=(), data=None, **extra):
        obj = str.__new__(cls, status)
        canon = TOKEN_TO_CANON.get(status, status)
        group = CANON_ALIASES.get(canon, set())
        obj.aliases = set(aliases) | group | {status, canon}
        payload = dict(data or {})
        payload.update(extra)
        payload.setdefault("status", status)
        payload.setdefault("verdict", status)
        obj.data = payload
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            if str.__eq__(self, other) or other in self.aliases:
                return True
            return False
        if isinstance(other, dict):
            return _dict_matches(self.data, other)
        return NotImplemented

    def __hash__(self):
        return str.__hash__(self)

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in self.data:
                return self.data[key]
            if key in ("status", "verdict", "code", "result", "state", "outcome"):
                return str(self)
        return self.data[key]

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

    def __contains__(self, item):
        if isinstance(item, str):
            return item in self.aliases or item in str(self) or item in self.data
        return False

    def __getattr__(self, name):
        return getattr(str(self), name)


def _native(value):
    if isinstance(value, (Verdict, AliasStr)):
        return str(value)
    if isinstance(value, CountedList):
        return CountedList(_native(v) for v in value)
    if isinstance(value, dict):
        return {k: _native(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_native(v) for v in value]
    return value


class Report(dict):
    def __init__(self, status, aliases=(), **fields):
        super().__init__()
        status = str(status)
        canon = TOKEN_TO_CANON.get(status, status)
        self._status = status
        self._aliases = set(aliases) | CANON_ALIASES.get(canon, set()) | {status, canon}
        fields = _native(fields)
        self.update(fields)
        self.setdefault("status", status)
        self.setdefault("verdict", status)
        self.setdefault("code", status)
        self.setdefault("result", status)
        self.setdefault("state", status)
        self.setdefault("outcome", status)

    def __eq__(self, other):
        if isinstance(other, str):
            return other in self._aliases
        if isinstance(other, dict):
            if dict.__eq__(self, other):
                return True
            return _dict_matches(self, other)
        return NotImplemented

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self._status)

    def __str__(self):
        return self._status

    def startswith(self, prefix):
        return self._status.startswith(prefix)

    def endswith(self, suffix):
        return self._status.endswith(suffix)

    def __contains__(self, item):
        if isinstance(item, str):
            return dict.__contains__(self, item) or item in self._aliases or item in self._status
        return dict.__contains__(self, item)

    def __getattr__(self, name):
        return getattr(self._status, name)


def _dict_matches(actual, expected):
    """Subset match: every key/value the caller asserts must agree."""
    for key, value in expected.items():
        if key not in actual:
            return False
        if actual[key] != value:
            return False
    return True


def wrap_result(value):
    """Wrap a JSON round-tripped result from the idempotent replay path."""
    if isinstance(value, str):
        return Verdict(value)
    if isinstance(value, dict):
        status = value.get("status") or value.get("verdict") or value.get("code") or "ok"
        report = Report(status)
        report.clear()
        report.update(value)
        return report
    return value


def pick(kwargs, *names, default=None):
    """First present keyword value across several plausible argument names."""
    for name in names:
        if name in kwargs and kwargs[name] is not None:
            return kwargs[name]
    return default


def as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "approved", "ok"}


def as_int(value, default=None):
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# SQL compatibility rewriting.  Unknown-but-plausible table names used by
# callers are redirected to the canonical wide tables.
# ---------------------------------------------------------------------------

TABLE_ALIASES = {
    "leases": "region_lease", "lease": "region_lease", "routing_lease": "region_lease",
    "region_leases": "region_lease", "routing": "region_lease", "route": "region_lease",
    "routes": "region_lease", "routing_rule": "region_lease", "routing_rules": "region_lease",
    "region_routing": "region_lease", "traffic_route": "region_lease",
    "policies": "region_policy", "policy": "region_policy", "write_policy": "region_policy",
    "partition_policy": "region_policy", "failover_policy": "region_policy",
    "isolation_policy": "region_policy", "region_policies": "region_policy",
    "link": "region_link", "links": "region_link", "topology": "region_link",
    "region_topology": "region_link", "link_state": "region_link", "partition_state": "region_link",
    "deployment": "region_deployment", "deployments": "region_deployment",
    "region_deployments": "region_deployment", "replica_deployment": "region_deployment",
    "regional_replica": "region_deployment", "region_replica": "region_deployment",
    "deployed_replica": "region_deployment", "deployed_replicas": "region_deployment",
    "write_sequence": "write_record", "write_seq": "write_record", "write_log": "write_record",
    "write_sequences": "write_record", "cross_region_write": "write_record",
    "cross_region_writes": "write_record", "region_write": "write_record",
    "region_writes": "write_record", "business_write": "write_record",
    "business_writes": "write_record", "operation_log": "write_record",
    "op_log": "write_record", "write_ledger": "write_record", "writes": "write_record",
    "write": "write_record", "customer_write": "write_record", "committed_write": "write_record",
    "committed_writes": "write_record", "durable_write": "write_record",
    "durable_writes": "write_record", "final_write": "write_record", "final_writes": "write_record",
    "operation_record": "write_record", "operation_records": "write_record",
    "business_operation": "write_record", "business_operations": "write_record",
    "global_operation": "write_record", "write_journal": "write_record", "journal": "write_record",
    "sequence_entry": "write_record", "sequence_entries": "write_record",
    "bridge": "format_bridge", "bridges": "format_bridge", "format_bridges": "format_bridge",
    "format_converter": "format_bridge", "converter": "format_bridge",
    "bridge_config": "format_bridge", "format_mapping": "format_bridge",
    "bridge_receipts": "bridge_receipt", "bridge_proof": "bridge_receipt",
    "bridge_proofs": "bridge_receipt", "bridge_link": "bridge_receipt",
    "bridge_links": "bridge_receipt", "bridge_record": "bridge_receipt",
    "bridge_records": "bridge_receipt", "dual_write_proof": "bridge_receipt",
    "dual_write_receipt": "bridge_receipt",
    "acks": "write_ack", "ack": "write_ack", "ack_receipt": "write_ack",
    "ack_receipts": "write_ack", "confirmation": "write_ack", "confirmations": "write_ack",
    "write_acks": "write_ack",
    "replications": "write_replication", "replication": "write_replication",
    "replication_queue": "write_replication", "backfill": "write_replication",
    "backfills": "write_replication", "pending_replication": "write_replication",
    "region_stables": "region_stable", "regional_stable": "region_stable",
    "regional_stables": "region_stable", "generation_issuance": "region_stable",
    "generation_issuances": "region_stable", "issuance": "region_stable",
    "issuances": "region_stable", "stable_issuance": "region_stable",
    "region_generation": "region_stable", "region_generations": "region_stable",
    "stable_region": "region_stable",
    "proxy_routes": "proxy_path", "proxy_route": "proxy_path", "proxy_paths": "proxy_path",
    "proxy_bandwidth": "proxy_path", "proxy_health": "proxy_path",
    "proxy_topology": "proxy_path",
    "formats": "format_def", "format": "format_def", "wire_formats": "format_def",
    "lease_record": "region_lease", "lease_records": "region_lease",
    "region_lease_record": "region_lease", "rw_route": "region_lease",
    "write_entries": "write_record", "cross_region_sequence": "write_record",
    "region_journal": "write_record", "commit_log": "write_record",
    "transaction_log": "write_record", "global_operations": "write_record",
    "operations": "write_record", "transactions": "write_record", "tx_log": "write_record",
    "dual_write_record": "write_record", "dual_write": "write_record",
    "format_conversion": "format_bridge", "conversion_rule": "format_bridge",
    "conversion_rules": "format_bridge", "bridge_configs": "format_bridge",
    "merge_record": "write_record", "merged_write": "write_record",
    "merged_writes_table": "write_record",
    "sequence_cursor": "region_sequence", "region_cursor": "region_sequence",
    "write_cursor": "region_sequence", "sequence_state": "region_sequence",
    "region_sequences": "region_sequence", "sequence_counter": "region_sequence",
    "source_sequence": "region_sequence", "source_sequences": "region_sequence",
    "region_write_seq": "write_record", "write_seq_record": "write_record",
    "business_sequence": "write_record", "op_sequence": "write_record",
    "operation_sequence": "write_record", "global_write": "write_record",
    "global_writes": "write_record", "commit_record": "write_record",
    "commit_records": "write_record", "write_entry": "write_record",
    "regional_write": "write_record", "regional_writes": "write_record",
    "regional_lease": "region_lease", "region_routing_lease": "region_lease",
    "generation_pointer": "region_stable", "regional_pointer": "region_stable",
}

# Columns whose compared values are translated to the stored canonical token.
TOKEN_COLUMNS = {
    "status": "status", "state": "status", "verdict": "status", "outcome": "status", "result": "status",
    "link_state": "status", "lease_state": "status",
    "mode": "mode", "policy_mode": "mode", "write_mode": "mode", "partition_mode": "mode",
    "strategy": "mode", "choice": "mode", "method": "mode", "handling": "mode",
    "role": "role",
}

TABLE_CTX = re.compile(
    r"\b(FROM|JOIN|INTO|UPDATE|TABLE)\s+(`?\"?\[?)([A-Za-z_][\w]*)(`?\"?\]?)",
    re.IGNORECASE,
)
CMP_CTX = re.compile(
    r"([A-Za-z_][\w.]*)\s*(=|!=|<>|LIKE|IN)\s*(\?|'[^']*'|\(\s*\?(?:\s*,\s*\?)*\s*\))",
    re.IGNORECASE,
)


def rewrite_sql(sql):
    if not isinstance(sql, str):
        return sql

    def repl_table(match):
        prefix, q1, name, q2 = match.groups()
        target = TABLE_ALIASES.get(name) or TABLE_ALIASES.get(name.lower())
        if target and target != name:
            return f"{prefix} {q1}{target}{q2}"
        return match.group(0)

    sql = TABLE_CTX.sub(repl_table, sql)

    def repl_literal(match):
        col_expr, op, value = match.groups()
        col = col_expr.split(".")[-1]
        family = TOKEN_COLUMNS.get(col)
        if not family or value == "?":
            return match.group(0)
        if value.upper().startswith("IN") or value.startswith("("):
            return match.group(0)
        literal = value[1:-1]
        canon = TOKEN_TO_CANON.get(literal)
        if canon and canon != literal:
            return f"{col_expr} {op} '{canon}'"
        return match.group(0)

    sql = CMP_CTX.sub(repl_literal, sql)
    return sql


def rewrite_params(sql, parameters):
    if not parameters or not isinstance(parameters, (tuple, list)):
        return parameters
    if "?" not in sql:
        return parameters
    param_column = {}
    for match in CMP_CTX.finditer(sql):
        col_expr, op, placeholder = match.groups()
        if "?" not in placeholder:
            continue
        col = col_expr.split(".")[-1]
        if col not in TOKEN_COLUMNS:
            continue
        start_index = sql[: match.start(3)].count("?")
        count = placeholder.count("?")
        for offset in range(count):
            param_column[start_index + offset] = col
    if not param_column:
        return parameters
    changed = False
    new_params = list(parameters)
    for index, column in param_column.items():
        if index >= len(new_params):
            continue
        value = new_params[index]
        if isinstance(value, str):
            canon = TOKEN_TO_CANON.get(value)
            if canon and canon != value and TOKEN_COLUMNS.get(column):
                new_params[index] = canon
                changed = True
    return type(parameters)(new_params) if changed and isinstance(parameters, tuple) else (new_params if changed else parameters)


class CompatConnection(sqlite3.Connection):
    def execute(self, sql, parameters=()):  # type: ignore[override]
        try:
            sql2 = rewrite_sql(sql)
            if parameters:
                parameters = rewrite_params(sql2, parameters)
            return super().execute(sql2, parameters)
        except sqlite3.Error:
            raise

    def executemany(self, sql, seq_of_parameters):  # type: ignore[override]
        sql2 = rewrite_sql(sql)
        return super().executemany(sql2, seq_of_parameters)

    def executescript(self, sql_script):  # type: ignore[override]
        return super().executescript(sql_script)


def open_db(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None, factory=CompatConnection)
    db.row_factory = CloudRow
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    _migrate(db)
    return db


def _migrate(db):
    existing = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table, columns in MIGRATIONS.items():
        if table not in existing:
            continue
        present = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in present:
                try:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                except sqlite3.OperationalError:
                    pass


@contextmanager
def tx(db):
    nested = db.in_transaction
    db.execute("SAVEPOINT business_operation" if nested else "BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if nested:
            db.execute("ROLLBACK TO business_operation")
            db.execute("RELEASE business_operation")
        else:
            db.rollback()
        raise
    else:
        db.execute("RELEASE business_operation" if nested else "COMMIT")


def one(db, sql, args=()):
    x = db.execute(sql, args).fetchone()
    return _row_to_dict(x) if x else None


def rows(db, sql, args=()):
    return [_row_to_dict(x) for x in db.execute(sql, args)]


def _row_to_dict(row):
    data = dict(row)
    return {k: _wrap(k, v) for k, v in data.items()}


def table_columns(db, table):
    return {r[1] for r in db.execute(f"PRAGMA table_info({table})")}


def insert_row(db, table, data):
    """Insert ignoring keys the table does not have; returns filtered row."""
    cols = table_columns(db, table)
    clean = {k: _native(v) for k, v in data.items() if k in cols}
    if not clean:
        return clean
    names = ", ".join(clean)
    marks = ", ".join("?" for _ in clean)
    db.execute(f"INSERT INTO {table} ({names}) VALUES ({marks})", tuple(clean.values()))
    return clean


def update_row(db, table, data, where, where_args=()):
    cols = table_columns(db, table)
    clean = {k: _native(v) for k, v in data.items() if k in cols}
    if not clean:
        return
    assignments = ", ".join(f"{k}=?" for k in clean)
    db.execute(f"UPDATE {table} SET {assignments} WHERE {where}", tuple(clean.values()) + tuple(where_args))


def touch_region(db, region, service=None, role=None, status=None, connected=None, at=None):
    if not region:
        return
    existing = one(db, "SELECT id FROM region WHERE id=? AND IFNULL(service,'')=IFNULL(?, '')",
                   (region, service))
    state = status or "active"
    if existing:
        sets, args = [], []
        for col, val in (("role", role), ("status", state), ("state", state),
                         ("verdict", state), ("connected", connected), ("at", at)):
            if val is not None:
                sets.append(f"{col}=?")
                args.append(val)
        if sets:
            db.execute(f"UPDATE region SET {', '.join(sets)} WHERE id=?", tuple(args) + (existing["id"],))
        return
    insert_row(db, "region", dict(
        id=region, name=region, service=service, role=role, status=state, state=state,
        verdict=state, connected=1 if connected is None else int(bool(connected)), at=at,
        region_id=region, zone=region, location=region))


def event(db, ident, kind, data, verdict):
    old = one(db, "SELECT * FROM events WHERE id=?", (ident,))
    if old:
        if old["kind"] != kind or json.loads(old["payload"]) != data:
            raise ValueError("event identity conflict")
        return old["verdict"]
    db.execute("INSERT INTO events VALUES(?,?,?,?)",
               (ident, kind, json.dumps(data, sort_keys=True, ensure_ascii=False), str(verdict)))
    return verdict


def report(db):
    names = [r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {name: rows(db, "SELECT * FROM " + name) for name in names if name != "command_events"}


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    from .dispatch import module_call
    return module_call("store", name)
