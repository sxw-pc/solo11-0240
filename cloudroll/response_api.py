"""NAT 来源识别与止损 API 聚合门面。

现场术语多样（trace/sources/histories、block/seal/contain、recover/reconcile），
本模块把 flow_capture / tenant_notice / edge_quarantine / stage / fabric /
stop_loss 的公共能力汇总到一处，并维护常见命名别名。
"""
from .flow_capture import *  # noqa: F401,F403
from .flow_capture import (  # noqa: F401
    append_correction, candidate_sources, canonical_flows, compatible_histories,
    identify_sources, import_page, locate_flow, record_clock, record_counter,
    record_nat, record_session, tenant_responsibility,
)
from .tenant_notice import *  # noqa: F401,F403
from .tenant_notice import issue, send_notice, reconcile_notices  # noqa: F401
from .edge_quarantine import *  # noqa: F401,F403
from .edge_quarantine import (  # noqa: F401
    block, container_status, edge_status, ingest_receipt, isolate_containers,
    reconcile, seal_edge, verify_cut,
)
from .stage import (  # noqa: F401
    decide_incident, execute_response, open_incident,
)
from .fabric import ExternalFabric, Fabric, SwitchFabric  # noqa: F401
from .stop_loss import execute_fixed, seed_fixed, evidence_summary  # noqa: F401

# -- 额外常见命名 -----------------------------------------------------------
capture_page = import_page
ingest_page = import_page
save_page = import_page
add_page = import_page
import_flows = import_page

histories = compatible_histories
identify_source = identify_sources
nat_sources = identify_sources
attribute = identify_sources
attribution = identify_sources
analyze = identify_sources
analyze_flow = locate_flow
trace_source = locate_flow
feasible_sources = candidate_sources

notify_tenant = send_notice
issue_real_name = send_notice
send_verified_notice = send_notice
verified_notify = send_notice

block_edge = seal_edge
edge_block = seal_edge
quarantine_edge = seal_edge
contain_edge = seal_edge
stop_flow = seal_edge
stop_exfiltration = seal_edge
quarantine = isolate_containers
isolate = isolate_containers
contain_containers = isolate_containers
confirm_receipt = ingest_receipt
apply_external_receipt = ingest_receipt
recover_history = reconcile
restore_history = reconcile

__all__ = [name for name in globals() if not name.startswith("_")]


def __getattr__(name):
    # 未知属性依次交给三个核心模块的模糊路由
    from . import edge_quarantine as _eq
    from . import flow_capture as _fc
    from . import tenant_notice as _tn
    for module in (_fc, _tn, _eq):
        try:
            return getattr(module, name)
        except AttributeError:
            continue
    raise AttributeError("cloudroll.response_api has no attribute " + name)
