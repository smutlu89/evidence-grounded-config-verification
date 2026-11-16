"""Layer 2 prompt template (fixed before the evaluation runs)."""
import json
from . import site

INTENTS = [
    ("I1", "SCADA isolation", "Corporate IT (CORP), the Internet (OUTSIDE) and vendor VPN users (VENDOR) must not be able to open connections directly into the OT side (OT or MGMT)."),
    ("I2", "DMZ mediation", "Traffic between the OT side (OT, MGMT) and any other zone, in either direction, must use only the approved cross-zone services; vendor VPN users may reach only the jump host."),
    ("I3", "Boundary enforcement", "Zone VLANs stay separated at layer 2: OT-facing ports are access ports in VLAN 10, only OT-facing ports are active in VLAN 10, other ports stay in their zone VLAN, trunks carry only their approved VLAN sets, and switches have no routed VLAN interfaces (SVIs with an IP address) for zone VLANs."),
    ("I4", "Management-plane restriction", "Device management follows the management policy in the registry."),
    ("I5", "Baseline consistency", "Every deviation from the approved baseline is reported for reconciliation."),
]

HEADER = """You are Layer 2 ("evidence-constrained reasoning") of a configuration verification pipeline for the OT network of a power plant.

You never see raw device configurations. You receive:
  1. the site's zone registry and policies,
  2. the security intents to check,
  3. evidence records extracted deterministically from the current configuration snapshots of five devices, each with an anchor of the form device:line,
  4. baseline-delta records listing every difference from the approved baseline (anchor device:line for a line in the current snapshot, device:base:line for a line that exists only in the baseline).

Task: find the evidence that violates the intents and return candidate findings. A deterministic validator re-checks every candidate against the evidence; candidates that cite anchors that do not exist, or claim something the cited records do not show, are discarded and are not returned to you. Do not speculate beyond the evidence. If an intent or question is too vague to map onto the registry, do not guess: set clarification_flag to true and ask a question.

How to read the evidence:
  - acl_entry records belong to the ACL named in "acl" and are evaluated in ascending "pos" order; the first matching entry decides. A permit is effective only for traffic that no earlier entry of the same ACL already matches. Addresses are CIDR (0.0.0.0/0 = any). dst_ports is [low, high]; if absent, all ports.
  - acl_binding records show where an ACL is applied; an ACL that is not bound has no effect. An ACL bound with vpn-filter applies to VENDOR traffic.
  - interface records describe switch ports, SVIs and firewall interfaces. Other records cover vty lines, SNMP, logging, NTP, HTTP servers, firewall management access and routes.

Citing:
  - ACL problems: cite the effective permit entry (or entries) that creates the forbidden path.
  - VLAN, trunk and SVI problems: cite the interface record.
  - Management problems: cite the vty, snmp_community, global, mgmt_access, snmp_host or logging_host record.
  - Baseline consistency: cite the anchor of each baseline_delta record.
  - Use zone names exactly as in the registry (OT, MGMT, DMZ, CORP, VENDOR, OUTSIDE) for source_zone and destination_zone of I1 and I2 findings; use "n/a" for I3, I4 and I5.
"""

OUTPUT = """OUTPUT FORMAT
Return exactly one JSON object and nothing else (no prose, no code fences):
{"candidates": [{"intent_id": "<I1..I5>", "source_zone": "<zone or n/a>", "destination_zone": "<zone or n/a>",
  "protocol_or_port": "<e.g. tcp/22, ip, n/a>", "action": "<permit, enabled, assigned, changed, ...>",
  "evidence_types": ["<record types>"], "constraint": "must_not_exist",
  "anchors": ["<anchor copied exactly from the evidence>"], "claim": "<one sentence>",
  "remediation": "<one sentence, or empty>", "clarification_flag": false}],
 "clarifications": [{"intent_id": "<I1..I5>", "question": "<question to the engineer>"}]}
Use an empty list where there is nothing to report."""


def _compact(r):
    return {k: v for k, v in r.items() if k != "device"}


def build(records, deltas, question=None):
    parts = [HEADER, "ZONE REGISTRY", site.registry_text(), ""]
    if question is None:
        parts.append("INTENTS TO CHECK")
        parts += [f"  {i} {name}: {text}" for i, name, text in INTENTS]
    else:
        parts.append("INTENT LIBRARY (reference)")
        parts += [f"  {i} {name}: {text}" for i, name, text in INTENTS]
        parts += ["", "OPERATOR QUESTION", f'  "{question}"',
                  "Answer only this question: decide which intent(s) it refers to and check those. If it is too vague to map onto "
                  "the registry, set clarification_flag to true for the intent(s) you considered and ask a question instead of guessing."]
    parts += ["", f"EVIDENCE RECORDS ({len(records)})"]
    parts += [json.dumps(_compact(r), separators=(",", ":")) for r in records]
    parts += ["", f"BASELINE DELTAS ({len(deltas)})"]
    parts += [json.dumps(_compact(d), separators=(",", ":")) for d in deltas] or ["(none)"]
    parts += ["", OUTPUT]
    return "\n".join(parts)
