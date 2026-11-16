"""Site data for the synthetic three-zone energy topology (zone registry).

Everything in this file is deterministic site knowledge that a plant would keep
under change control: zone address ranges, interface-to-zone bindings, approved
cross-zone services, switch port roles, approved trunk VLAN sets, the management
policy and the register of planned outages.
"""
import ipaddress as ipa

ZONES = {
    "OT":     {"net": "10.10.10.0/24",  "vlan": 10, "desc": "control assets (PLC, RTU, HMI, SCADA servers, EWS 10.10.10.40)"},
    "MGMT":   {"net": "10.10.99.0/24",  "vlan": 99, "desc": "network management (NMS 10.10.99.50, syslog 10.10.99.60)"},
    "DMZ":    {"net": "10.10.20.0/24",  "vlan": 20, "desc": "historian 10.10.20.10, NTP 10.10.20.5, jump host 10.10.20.30, patch server 10.10.20.40"},
    "CORP":   {"net": "192.168.30.0/24", "vlan": 30, "desc": "corporate IT (reporting server 192.168.30.20)"},
    "VENDOR": {"net": "172.16.50.0/24", "vlan": None, "desc": "remote-access VPN address pool for vendors"},
}
OUTSIDE = "OUTSIDE"          # any address not inside a listed zone
PROTECTED = ("OT", "MGMT")   # the OT side of the boundary

def net(z):
    return ipa.ip_network(ZONES[z]["net"])

ANY = ipa.ip_network("0.0.0.0/0")

# interface (or VPN filter) -> zone of the traffic that enters through it
IF_ZONE = {
    ("fw-01", "outside"): "OUTSIDE",
    ("fw-01", "corp"): "CORP",
    ("fw-01", "dmz"): "DMZ",
    ("fw-01", "ot"): "OT",
    ("fw-01", "mgmt"): "MGMT",
    ("rtr-01", "GigabitEthernet0/0/0"): "OUTSIDE",
}
VPN_FILTER_ZONE = "VENDOR"   # ACLs bound with 'vpn-filter value <ACL>' filter VENDOR traffic

# approved cross-zone services: (id, source net, destination net, protocol, port)
APPROVED = [
    ("A1", "10.10.10.20/31", "10.10.20.10/32", "tcp", 5450),   # SCADA servers .20/.21 -> historian
    ("A1", "10.10.10.22/31", "10.10.20.10/32", "tcp", 5450),   # SCADA servers .22/.23 -> historian
    ("A2", "10.10.10.0/24", "10.10.20.5/32", "udp", 123),      # OT -> NTP
    ("A2", "10.10.99.0/24", "10.10.20.5/32", "udp", 123),      # MGMT -> NTP
    ("A3", "10.10.10.0/24", "10.10.20.40/32", "tcp", 8530),    # OT -> patch server
    ("A4", "10.10.20.30/32", "10.10.10.40/32", "tcp", 3389),   # jump host -> EWS
    ("A5", "192.168.30.0/24", "10.10.20.10/32", "tcp", 443),   # CORP -> historian web
    ("A5", "192.168.30.0/24", "10.10.20.30/32", "tcp", 3389),  # CORP -> jump host
    ("A6", "10.10.20.10/32", "192.168.30.20/32", "tcp", 443),  # historian -> reporting server
    ("A7", "172.16.50.0/24", "10.10.20.30/32", "tcp", 3389),   # VENDOR -> jump host
]
APPROVED_TEXT = [
    "A1 SCADA servers 10.10.10.20-10.10.10.23 -> historian 10.10.20.10 tcp/5450",
    "A2 OT and MGMT -> NTP server 10.10.20.5 udp/123",
    "A3 OT -> patch server 10.10.20.40 tcp/8530",
    "A4 jump host 10.10.20.30 -> engineering workstation 10.10.10.40 tcp/3389",
    "A5 CORP -> historian 10.10.20.10 tcp/443; CORP -> jump host 10.10.20.30 tcp/3389",
    "A6 historian 10.10.20.10 -> reporting server 192.168.30.20 tcp/443",
    "A7 VENDOR -> jump host 10.10.20.30 tcp/3389 (no other destination)",
]

# switch port roles (port numbers on GigabitEthernet1/0/x)
PORT_ROLES = {
    "sw-ot-01":   {"OT": set(range(1, 17)), "UNUSED": set(range(17, 24))},
    "sw-it-01":   {"CORP": set(range(1, 21)), "UNUSED": set(range(21, 24))},
    "sw-core-01": {"DMZ": set(range(1, 5)), "UNUSED": set(range(5, 21)) | {23}},
}
ROLE_VLAN = {"OT": 10, "CORP": 30, "DMZ": 20, "UNUSED": 999}

TRUNKS = {
    ("sw-ot-01", "GigabitEthernet1/0/24"): {10, 99},
    ("sw-it-01", "GigabitEthernet1/0/24"): {30, 99},
    ("sw-core-01", "GigabitEthernet1/0/21"): {30, 99},
    ("sw-core-01", "GigabitEthernet1/0/22"): {10, 99},
    ("sw-core-01", "GigabitEthernet1/0/24"): {10, 20, 30, 99},
}
ZONE_VLANS = {10, 20, 30}

MGMT_NET = ipa.ip_network("10.10.99.0/24")

# planned outage register (authorized shutdowns, Unit 2 outage window)
OUTAGES = {("sw-ot-01", f"GigabitEthernet1/0/{p}") for p in (9, 10, 11, 12)}


def port_role(device, ifname):
    if device not in PORT_ROLES or not ifname.startswith("GigabitEthernet1/0/"):
        return None
    n = int(ifname.rsplit("/", 1)[1])
    for role, rng in PORT_ROLES[device].items():
        if n in rng:
            return role
    return None


def registry_text():
    """Zone registry as given to the language model (Layer 2)."""
    out = ["ZONES (name, network, VLAN, contents)"]
    for z, d in ZONES.items():
        v = d["vlan"] if d["vlan"] else "-"
        out.append(f"  {z:<7} {d['net']:<16} VLAN {v:<4} {d['desc']}")
    out.append("  OUTSIDE any address not inside the zones above")
    out.append("INTERFACE ZONES (traffic entering through the interface comes from this zone)")
    out.append("  fw-01: outside=OUTSIDE, corp=CORP, dmz=DMZ, ot=OT, mgmt=MGMT; ACLs bound with vpn-filter apply to VENDOR traffic")
    out.append("  rtr-01: GigabitEthernet0/0/0=OUTSIDE")
    out.append("APPROVED CROSS-ZONE SERVICES (everything else between the OT side (OT, MGMT) and other zones is forbidden)")
    out += ["  " + t for t in APPROVED_TEXT]
    out.append("SWITCH PORT ROLES (GigabitEthernet1/0/x)")
    out.append("  sw-ot-01: ports 1-16 OT-facing (access, VLAN 10); ports 17-23 unused (VLAN 999, shutdown); port 24 uplink trunk")
    out.append("  sw-it-01: ports 1-20 CORP access (VLAN 30); ports 21-23 unused; port 24 uplink trunk")
    out.append("  sw-core-01: ports 1-4 DMZ servers (access, VLAN 20); ports 5-20 and 23 unused (VLAN 999, shutdown); ports 21, 22, 24 trunks")
    out.append("  Only OT-facing ports may be active in VLAN 10.")
    out.append("APPROVED TRUNKS (allowed VLAN sets; any other trunk is unauthorized)")
    out.append("  sw-ot-01 Gi1/0/24 {10,99}; sw-it-01 Gi1/0/24 {30,99}; sw-core-01 Gi1/0/21 {30,99}, Gi1/0/22 {10,99}, Gi1/0/24 {10,20,30,99}")
    out.append("  Switches must not have routed VLAN interfaces (SVIs with an IP address) for zone VLANs 10, 20 or 30.")
    out.append("MANAGEMENT POLICY")
    out.append("  Device management (SSH, HTTPS/ASDM, SNMP) only from MGMT 10.10.99.0/24 and, on fw-01, only on the mgmt interface.")
    out.append("  Telnet must not be enabled anywhere. IOS HTTP/HTTPS servers must be disabled. SNMP communities must be read-only")
    out.append("  and restricted by an ACL that permits only MGMT hosts. Logging and SNMP trap destinations must be inside MGMT.")
    out.append("PLANNED OUTAGES (authorized shutdowns): sw-ot-01 Gi1/0/9, Gi1/0/10, Gi1/0/11, Gi1/0/12 (Unit 2 outage window)")
    return "\n".join(out)
