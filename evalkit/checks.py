"""Deterministic intent checks (used by the Layer 3 gate and by the rule-only comparator).

check(records, deltas) -> list of findings
    {"intent": "I1".."I5", "anchor": record or delta anchor, "zones": (src, dst) or None,
     "label": "violation" | "baseline_item" | "informational", "related": [anchors], "reason": str}

I1 SCADA isolation, I2 DMZ mediation, I3 boundary enforcement, I4 management-plane restriction,
I5 baseline consistency. ACL evaluation is order-aware (first match) and binding-aware.
"""
import ipaddress as ipa
from . import site

N = ipa.ip_network
FULL = [0, 65535]


def _sub(a, b):          # a within b
    return a.version == b.version and a.subnet_of(b)


def _inter(a, b):
    if not a.overlaps(b):
        return None
    return a if a.subnet_of(b) else b


def _ports(e):
    return e.get("dst_ports") or FULL


def _covers(e, S):
    """Does ACL entry e match every packet of space S=(src, dst, proto, ports)?"""
    src, dst, proto, ports = S
    if e.get("src_ports") or "established" in e.get("flags", []):
        return False
    if not _sub(src, N(e["src"])) or not _sub(dst, N(e["dst"])):
        return False
    if e["proto"] == "ip":
        return True
    if e["proto"] != proto:
        return False
    lo, hi = _ports(e)
    return lo <= ports[0] and ports[1] <= hi


def _approved(S):
    src, dst, proto, ports = S
    for _, a_src, a_dst, a_proto, a_port in site.APPROVED:
        if _sub(src, N(a_src)) and _sub(dst, N(a_dst)) and proto == a_proto and ports == [a_port, a_port]:
            return True
    return False


def zone_of_addr(n):
    for z in site.ZONES:
        if _sub(n, site.net(z)):
            return z
    if n == site.ANY:
        return "ANY"
    return "OUTSIDE"


def binding_zone(b):
    if b["interface"].startswith("vpn-filter"):
        return site.VPN_FILTER_ZONE
    return site.IF_ZONE.get((b["device"], b["interface"]))


def _acl_index(records):
    acls = {}
    for r in records:
        if r["type"] == "acl_entry":
            acls.setdefault((r["device"], r["acl"]), []).append(r)
    for k in acls:
        acls[k].sort(key=lambda r: r["pos"])
    return acls


def _acl_findings(records):
    out = []
    acls = _acl_index(records)
    for b in [r for r in records if r["type"] == "acl_binding" and r["direction"] == "in"]:
        zs = binding_zone(b)
        entries = acls.get((b["device"], b["acl"]), [])
        if zs is None or not entries or entries[0]["kind"] != "extended":
            continue
        for k, r in enumerate(entries):
            if r["action"] != "permit":
                continue
            prior = entries[:k]
            rsrc, rdst = N(r["src"]), N(r["dst"])
            src = rsrc if zs == "OUTSIDE" else _inter(rsrc, site.net(zs))
            if src is None:
                continue
            proto, ports = r["proto"], _ports(r)
            # flows into the OT side
            for P in site.PROTECTED:
                if zs in site.PROTECTED:
                    continue
                dst = _inter(rdst, site.net(P))
                if dst is None:
                    continue
                S = (src, dst, proto, ports)
                if any(_covers(e, S) for e in prior) or _approved(S):
                    continue
                if zs in ("CORP", "OUTSIDE", "VENDOR"):
                    out.append({"intent": "I1", "anchor": r["anchor"], "zones": (zs, P), "label": "violation",
                                "related": [b["anchor"]], "reason": f"effective permit from {zs} into {P}"})
                out.append({"intent": "I2", "anchor": r["anchor"], "zones": (zs, P), "label": "violation",
                            "related": [b["anchor"]], "reason": f"{zs} to {P} outside approved services"})
            # flows leaving the OT side
            if zs in site.PROTECTED and not any(_sub(rdst, site.net(P)) for P in site.PROTECTED):
                S = (src, rdst, proto, ports)
                if not (any(_covers(e, S) for e in prior) or _approved(S)):
                    out.append({"intent": "I2", "anchor": r["anchor"], "zones": (zs, zone_of_addr(rdst)),
                                "label": "violation", "related": [b["anchor"]],
                                "reason": f"{zs} egress outside approved services"})
            # vendor users may reach only the jump host
            if zs == "VENDOR" and not any(_sub(rdst, site.net(P)) for P in site.PROTECTED):
                S = (src, rdst, proto, ports)
                if not (any(_covers(e, S) for e in prior) or _approved(S)):
                    out.append({"intent": "I2", "anchor": r["anchor"], "zones": ("VENDOR", zone_of_addr(rdst)),
                                "label": "violation", "related": [b["anchor"]],
                                "reason": "vendor access beyond the jump host"})
    return out


def _std_acl_offenders(acls, device, name):
    """Entries of a standard ACL that permit sources outside MGMT (first match)."""
    entries = acls.get((device, name), [])
    bad = []
    for k, e in enumerate(entries):
        if e["action"] != "permit":
            continue
        s = N(e["src"])
        if _sub(s, site.MGMT_NET):
            continue
        if any(_sub(s, N(p["src"])) for p in entries[:k]):
            continue
        bad.append(e["anchor"])
    return bad


def _boundary_findings(records):
    out = []
    for r in records:
        if r["type"] != "interface" or not r["device"].startswith("sw-"):
            continue
        name, dev = r["name"], r["device"]
        f = lambda why: out.append({"intent": "I3", "anchor": r["anchor"], "zones": None, "label": "violation",
                                    "related": [], "reason": why})
        if name.startswith("Vlan"):
            v = int(name[4:])
            if v in site.ZONE_VLANS and "ip" in r:
                f(f"routed SVI for zone VLAN {v}")
            continue
        role = site.port_role(dev, name)
        mode = r.get("mode", "dynamic")
        vlan = r.get("access_vlan", 1)
        shut = r.get("shutdown", False)
        if (dev, name) in site.TRUNKS:
            if mode == "trunk":
                allowed = r.get("trunk_allowed", "all")
                if allowed == "all" or not set(allowed) <= site.TRUNKS[(dev, name)]:
                    f("trunk carries VLANs outside its approved set")
            continue
        if mode == "trunk":
            f("unauthorized trunk"); continue
        if role == "OT" and (mode != "access" or vlan != 10):
            f("OT-facing port not an access port in VLAN 10"); continue
        if role in ("CORP", "DMZ") and vlan != site.ROLE_VLAN[role]:
            f(f"{role} port assigned to VLAN {vlan}"); continue
        if role != "OT" and vlan == 10 and not shut:
            f("active non-OT port in VLAN 10")
    return out


def _mgmt_findings(records):
    out = []
    acls = _acl_index(records)
    add = lambda r, why, rel=(): out.append({"intent": "I4", "anchor": r["anchor"], "zones": None,
                                             "label": "violation", "related": list(rel), "reason": why})
    for r in records:
        t = r["type"]
        if t == "vty":
            ti = r.get("transport_input", [])
            if "telnet" in ti or "all" in ti:
                add(r, "telnet enabled on vty lines")
            if not r.get("access_class"):
                add(r, "vty lines without access-class")
            else:
                bad = _std_acl_offenders(acls, r["device"], r["access_class"])
                if bad:
                    add(r, "vty access-class permits non-MGMT sources", bad)
        elif t == "snmp_community":
            if r["mode"] == "RW":
                add(r, "SNMP read-write community")
            if not r.get("acl"):
                add(r, "SNMP community without ACL")
            else:
                bad = _std_acl_offenders(acls, r["device"], r["acl"])
                if bad:
                    add(r, "SNMP ACL permits non-MGMT sources", bad)
        elif t == "global" and r["setting"] in ("ip_http_server", "ip_http_secure_server") and r["enabled"]:
            add(r, "IOS HTTP server enabled")
        elif t == "mgmt_access":
            if r["service"] == "telnet":
                add(r, "telnet management enabled")
            elif r["interface"] != "mgmt" or not _sub(N(r["src"]), site.MGMT_NET):
                add(r, f"{r['service']} management allowed from outside MGMT")
        elif t in ("snmp_host", "logging_host"):
            if not _sub(N(r["address"] + "/32"), site.MGMT_NET):
                add(r, f"{t.replace('_', ' ')} outside MGMT")
    return out


def _baseline_findings(deltas):
    out = []
    for d in deltas:
        label = "baseline_item"
        if d["keyword"] == "shutdown" and d["change"] in ("added", "modified") and d["section"].startswith("interface "):
            if (d["device"], d["section"].split()[1]) in site.OUTAGES:
                label = "informational"
        out.append({"intent": "I5", "anchor": d["anchor"], "zones": None, "label": label,
                    "related": [d["record"]] if d.get("record") else [], "reason": f"{d['change']} {d['keyword']}"})
    return out


def check(records, deltas):
    return _acl_findings(records) + _boundary_findings(records) + _mgmt_findings(records) + _baseline_findings(deltas)
