"""Dataset generator: mutation suite, compliant set, latent set, scenarios S1-S3.

Every generated snapshot comes with ground truth (GT) written in terms of the
lines that a correct finding must cite. GT is resolved to anchors after all edits.
"""
import copy
import random
from functools import partial
from . import baseline as B

BASE_TS = "09:14:22 UTC Mon Oct 5 2026"
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


# ---------------------------------------------------------------- config edit helpers
def find(cfg, dev, text, start=0):
    hits = [i for i, l in enumerate(cfg[dev]) if l == text and i >= start]
    assert len(hits) >= 1, (dev, text)
    return hits[0]


def acl_lines(cfg, dev, name):
    return [i for i, l in enumerate(cfg[dev]) if l.startswith(f"access-list {name} extended ")]


def block(cfg, dev, header):
    s = find(cfg, dev, header)
    e = s + 1
    while e < len(cfg[dev]) and cfg[dev][e].startswith(" "):
        e += 1
    return s, e


def replace_in_block(cfg, dev, header, old, new):
    s, e = block(cfg, dev, header)
    i = find(cfg, dev, old, s)
    assert i < e, (dev, header, old)
    cfg[dev][i] = new
    return new


def delete_in_block(cfg, dev, header, old):
    s, e = block(cfg, dev, header)
    i = find(cfg, dev, old, s)
    assert i < e
    del cfg[dev][i]


def insert_in_block(cfg, dev, header, line, after=None):
    s, e = block(cfg, dev, header)
    pos = e if after is None else find(cfg, dev, after, s) + 1
    cfg[dev].insert(pos, line)


def gi(n):
    return f"interface GigabitEthernet1/0/{n}"


def ts(rng):
    d = rng.randint(6, 30)
    h, m, s = rng.randint(6, 18), rng.randint(0, 59), rng.randint(0, 59)
    day = DAYS[(d - 5) % 7]        # Oct 5 2026 is a Monday
    return f"{h:02d}:{m:02d}:{s:02d} UTC {day} Oct {d} 2026"


def touch(cfg, dev, stamp):
    """Update the volatile timestamp lines of a device (what an engineer's 'write memory' does)."""
    for i, l in enumerate(cfg[dev]):
        if l.startswith("! Last configuration change at "):
            cfg[dev][i] = f"! Last configuration change at {stamp} by netadmin"
        if l.startswith(": Written by "):
            cfg[dev][i] = f": Written by netadmin at {stamp.replace(' UTC', '.' + str(len(stamp) * 37 % 1000).zfill(3) + ' UTC')}"


# ---------------------------------------------------------------- GT specs
def L(dev, text):            # a snapshot line that a finding may cite
    return ("line", dev, text)


def H(dev, header):          # the section header (record anchor) that a finding may cite
    return ("line", dev, header)


def BL(dev, text):           # a baseline line (removed in the snapshot)
    return ("base", dev, text)


def gt(intents, accept, family, template, desc):
    if "I1" in intents and "I2" not in intents:     # ingress into the OT side also breaks DMZ mediation (I2)
        intents = intents + ["I2"]
    return {"intents": intents, "accept": accept, "family": family, "template": template, "desc": desc}


CORP_HOSTS = [f"192.168.30.{h}" for h in (11, 14, 23, 37, 45, 52, 61, 88, 102, 117, 140, 163)]
OT_HOSTS = ["10.10.10.20", "10.10.10.21", "10.10.10.31", "10.10.10.32", "10.10.10.33", "10.10.10.34", "10.10.10.40", "10.10.10.51"]
OT_PORTS = [502, 44818, 102, 20000, 3389, 22, 4840]
CORP_DENY_OT = "access-list CORP_IN extended deny ip 192.168.30.0 255.255.255.0 10.10.10.0 255.255.255.0 log"
CORP_ANY = ["access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 any eq https",
            "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 any eq www",
            "access-list CORP_IN extended permit udp 192.168.30.0 255.255.255.0 any eq domain"]


# ---------------------------------------------------------------- family (i): ACL permutations
def i01(c, r):
    line = f"access-list CORP_IN extended permit tcp host {r.choice(CORP_HOSTS)} host {r.choice(OT_HOSTS)} eq {r.choice(OT_PORTS)}"
    c["fw-01"].insert(acl_lines(c, "fw-01", "CORP_IN")[0], line)
    return [gt(["I1"], [L("fw-01", line)], "i", "i01", "new CORP host-to-OT permit at top of CORP_IN")]


def i02(c, r):
    i = find(c, "fw-01", CORP_DENY_OT)
    c["fw-01"][i] = CORP_DENY_OT.replace(" deny ", " permit ")
    return [gt(["I1"], [L("fw-01", c["fw-01"][i])], "i", "i02", "CORP-to-OT deny changed to permit")]


def i03(c, r):
    del c["fw-01"][find(c, "fw-01", CORP_DENY_OT)]
    return [gt(["I1"], [L("fw-01", x) for x in CORP_ANY], "i", "i03", "CORP-to-OT deny removed; broad CORP permits now reach OT")]


def i04(c, r):
    del c["fw-01"][find(c, "fw-01", CORP_DENY_OT)]
    c["fw-01"].insert(acl_lines(c, "fw-01", "CORP_IN")[-1] + 1, CORP_DENY_OT)
    return [gt(["I1"], [L("fw-01", x) for x in CORP_ANY], "i", "i04", "CORP-to-OT deny re-entered at the end of CORP_IN (below the broad permits)")]


def i05(c, r):
    old = "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 host 10.10.20.10 eq https"
    new = "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 10.10.0.0 255.255.0.0 eq https"
    c["fw-01"][find(c, "fw-01", old)] = new
    return [gt(["I1"], [L("fw-01", new)], "i", "i05", "historian web permit widened to 10.10.0.0/16 above the OT deny")]


def i06(c, r):
    old = "access-list OT_IN extended permit tcp host 10.10.10.20 host 10.10.20.10 eq 5450"
    new = "access-list OT_IN extended permit tcp host 10.10.10.20 any eq 5450"
    c["fw-01"][find(c, "fw-01", old)] = new
    return [gt(["I2"], [L("fw-01", new)], "i", "i06", "SCADA-to-historian permit widened to any destination")]


def i07(c, r):
    line = f"access-list OT_IN extended permit tcp 10.10.10.0 255.255.255.0 host 192.168.30.20 eq https"
    c["fw-01"].insert(find(c, "fw-01", "access-list OT_IN extended deny ip any any log"), line)
    return [gt(["I2"], [L("fw-01", line)], "i", "i07", "OT direct to corporate reporting server, bypassing the historian")]


def i08(c, r):
    old = "access-list DMZ_IN extended permit tcp host 10.10.20.30 host 10.10.10.40 eq 3389"
    new = "access-list DMZ_IN extended permit ip host 10.10.20.30 10.10.10.0 255.255.255.0"
    c["fw-01"][find(c, "fw-01", old)] = new
    return [gt(["I2"], [L("fw-01", new)], "i", "i08", "jump-host permit widened to all protocols and the whole OT subnet")]


def i09(c, r):
    line = f"access-list DMZ_IN extended permit tcp host 10.10.20.10 10.10.10.0 255.255.255.0 eq {r.choice([502, 44818, 102])}"
    c["fw-01"].insert(acl_lines(c, "fw-01", "DMZ_IN")[0], line)
    return [gt(["I2"], [L("fw-01", line)], "i", "i09", "historian allowed to poll OT devices directly")]


def i10(c, r):
    line = f"access-list VENDOR_VPN extended permit tcp 172.16.50.0 255.255.255.0 host {r.choice(OT_HOSTS)} eq {r.choice([3389, 22, 5900])}"
    c["fw-01"].insert(acl_lines(c, "fw-01", "VENDOR_VPN")[0], line)
    return [gt(["I1", "I2"], [L("fw-01", line)], "i", "i10", "vendor VPN pool allowed directly into OT")]


def i11(c, r):
    line = f"access-list OUTSIDE_IN extended permit tcp any host {r.choice(OT_HOSTS)} eq {r.choice([3389, 502, 22])}"
    c["fw-01"].insert(acl_lines(c, "fw-01", "OUTSIDE_IN")[0], line)
    return [gt(["I1"], [L("fw-01", line)], "i", "i11", "inbound permit from outside to an OT host")]


def i12(c, r):
    line = f" 85 permit tcp any 10.10.10.0 0.0.0.255 eq {r.choice([502, 20000, 102])}"
    insert_in_block(c, "rtr-01", "ip access-list extended EDGE_IN", line, after=" 80 permit udp any eq ntp host 203.0.113.2")
    return [gt(["I1"], [L("rtr-01", line)], "i", "i12", "edge router ACL permits Internet traffic to the OT subnet")]


def i13(c, r):
    line = f"access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 10.10.99.0 255.255.255.0 eq {r.choice(['ssh', 'https'])}"
    c["fw-01"].insert(acl_lines(c, "fw-01", "CORP_IN")[0], line)
    return [gt(["I1"], [L("fw-01", line)], "i", "i13", "corporate network allowed into the management VLAN")]


def i14(c, r):
    line = "access-list MGMT_IN extended permit ip 10.10.99.0 255.255.255.0 192.168.30.0 255.255.255.0"
    c["fw-01"].insert(find(c, "fw-01", "access-list MGMT_IN extended deny ip any any log"), line)
    return [gt(["I2"], [L("fw-01", line)], "i", "i14", "management VLAN allowed to reach the corporate network")]


def i15(c, r):
    old = "access-list OT_IN extended permit udp 10.10.10.0 255.255.255.0 host 10.10.20.5 eq ntp"
    new = "access-list OT_IN extended permit ip 10.10.10.0 255.255.255.0 host 10.10.20.5"
    c["fw-01"][find(c, "fw-01", old)] = new
    return [gt(["I2"], [L("fw-01", new)], "i", "i15", "NTP permit widened from udp/123 to all protocols")]


FAMILY_I = [i01, i02, i03, i04, i05, i06, i07, i08, i09, i10, i11, i12, i13, i14, i15]


# ---------------------------------------------------------------- family (ii): VLAN and trunk
def _vlan_change(c, dev, port, old, new, tmpl, desc):
    line = replace_in_block(c, dev, gi(port), f" switchport access vlan {old}", f" switchport access vlan {new}")
    return [gt(["I3"], [H(dev, gi(port)), L(dev, line)], "ii", tmpl, desc)]


def ii01(c, r, port=None):
    p = port or r.choice([1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16])
    return _vlan_change(c, "sw-ot-01", p, 10, 30, "ii01", f"OT-facing port Gi1/0/{p} moved to the corporate VLAN")


def ii02(c, r):
    p = r.choice([1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16])
    return _vlan_change(c, "sw-ot-01", p, 10, 20, "ii02", f"OT-facing port Gi1/0/{p} moved to the DMZ VLAN")


def ii03(c, r, port=None):
    p = port or r.randint(1, 18)
    return _vlan_change(c, "sw-it-01", p, 30, 10, "ii03", f"corporate port Gi1/0/{p} moved into the OT VLAN")


def _trunk_change(c, dev, port, old, new, tmpl, desc):
    line = replace_in_block(c, dev, gi(port), f" switchport trunk allowed vlan {old}", f" switchport trunk allowed vlan {new}")
    return [gt(["I3"], [H(dev, gi(port)), L(dev, line)], "ii", tmpl, desc)]


def ii04(c, r):
    return _trunk_change(c, "sw-ot-01", 24, "10,99", "10,30,99", "ii04", "OT switch uplink trunk now carries the corporate VLAN")


def ii05(c, r):
    return _trunk_change(c, "sw-core-01", 22, "10,99", "10,30,99", "ii05", "core trunk to the OT switch now carries the corporate VLAN")


def ii06(c, r):
    return _trunk_change(c, "sw-it-01", 24, "30,99", "10,30,99", "ii06", "IT switch uplink trunk now carries the OT VLAN")


def ii07(c, r):
    p = r.choice([1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16])
    line = replace_in_block(c, "sw-ot-01", gi(p), " switchport mode access", " switchport mode trunk")
    return [gt(["I3"], [H("sw-ot-01", gi(p)), L("sw-ot-01", line)], "ii", "ii07", f"OT-facing port Gi1/0/{p} set to trunk mode")]


def ii08(c, r):
    p = r.randint(5, 20)
    line = replace_in_block(c, "sw-core-01", gi(p), " switchport access vlan 999", " switchport access vlan 10")
    delete_in_block(c, "sw-core-01", gi(p), " shutdown")
    return [gt(["I3"], [H("sw-core-01", gi(p)), L("sw-core-01", line)], "ii", "ii08", f"unused core port Gi1/0/{p} activated in the OT VLAN")]


def ii09(c, r):
    i = find(c, "sw-core-01", "ip default-gateway 10.10.99.1")
    c["sw-core-01"][i:i] = ["interface Vlan10", " ip address 10.10.10.254 255.255.255.0", "!"]
    c["sw-core-01"].insert(find(c, "sw-core-01", "ip default-gateway 10.10.99.1") + 1, "ip routing")
    return [gt(["I3"], [H("sw-core-01", "interface Vlan10"), L("sw-core-01", " ip address 10.10.10.254 255.255.255.0")],
               "ii", "ii09", "routed SVI for the OT VLAN added on the core switch")]


FAMILY_II = None      # assembled in build() so that repeated templates get distinct parameters


# ---------------------------------------------------------------- family (iii): management services
IOS_DEVS = ["sw-ot-01", "sw-core-01", "sw-it-01", "rtr-01"]
SW_DEVS = ["sw-ot-01", "sw-core-01", "sw-it-01"]


def iii01(c, r, dev=None):
    d = dev or r.choice(IOS_DEVS)
    line = replace_in_block(c, d, "line vty 0 4", " transport input ssh", " transport input telnet ssh")
    return [gt(["I4"], [H(d, "line vty 0 4"), L(d, line)], "iii", "iii01", f"telnet enabled on vty 0 4 of {d}")]


def iii02(c, r):
    d = r.choice(SW_DEVS)
    delete_in_block(c, d, "line vty 0 4", " access-class VTY_MGMT in")
    return [gt(["I4"], [H(d, "line vty 0 4")], "iii", "iii02", f"access-class removed from vty 0 4 of {d}")]


def iii03(c, r):
    d = r.choice(SW_DEVS)
    line = " permit 192.168.30.0 0.0.0.255"
    insert_in_block(c, d, "ip access-list standard VTY_MGMT", line, after=" permit 10.10.99.0 0.0.0.255")
    return [gt(["I4"], [H(d, "line vty 0 4"), H(d, "line vty 5 15"), L(d, line)], "iii", "iii03", f"VTY_MGMT on {d} widened to the corporate subnet")]


def iii04(c, r, dev=None):
    d = dev or r.choice(IOS_DEVS)
    line = "snmp-server community <removed> RW"
    c[d].insert(find(c, d, "snmp-server community <removed> RO SNMP_NMS") + 1, line)
    return [gt(["I4"], [L(d, line)], "iii", "iii04", f"read-write SNMP community without ACL added on {d}")]


def iii05(c, r):
    d = r.choice(IOS_DEVS)
    i = find(c, d, "snmp-server community <removed> RO SNMP_NMS")
    c[d][i] = "snmp-server community <removed> RO"
    return [gt(["I4"], [L(d, c[d][i])], "iii", "iii05", f"SNMP community ACL removed on {d}")]


def iii06(c, r):
    d = r.choice(IOS_DEVS)
    i = find(c, d, "no ip http server")
    c[d][i] = "ip http server"
    return [gt(["I4"], [L(d, "ip http server")], "iii", "iii06", f"IOS HTTP server enabled on {d}")]


def iii07(c, r):
    line = "ssh 192.168.30.0 255.255.255.0 corp"
    c["fw-01"].insert(find(c, "fw-01", "ssh 10.10.99.0 255.255.255.0 mgmt") + 1, line)
    return [gt(["I4"], [L("fw-01", line)], "iii", "iii07", "firewall SSH management allowed from the corporate interface")]


def iii08(c, r):
    line = "http 0.0.0.0 0.0.0.0 outside"
    c["fw-01"].insert(find(c, "fw-01", "http 10.10.99.0 255.255.255.0 mgmt") + 1, line)
    return [gt(["I4"], [L("fw-01", line)], "iii", "iii08", "firewall ASDM/HTTPS management allowed from outside")]


def iii09(c, r):
    line = "telnet 10.10.10.0 255.255.255.0 ot"
    c["fw-01"].insert(find(c, "fw-01", "telnet timeout 5"), line)
    return [gt(["I4"], [L("fw-01", line)], "iii", "iii09", "telnet management enabled on the firewall OT interface")]


def iii10(c, r, dev=None):
    d = dev or r.choice(SW_DEVS)
    line = f"logging host 192.168.30.{r.choice([77, 80, 95])}"
    c[d].insert(find(c, d, "logging host 10.10.99.60") + 1, line)
    return [gt(["I4"], [L(d, line)], "iii", "iii10", f"syslog exported to a corporate host from {d}")]


FAMILY_III = None


# ---------------------------------------------------------------- family (iv): baseline-only deltas
def iv01(c, r):
    d = r.choice(SW_DEVS)
    c[d].insert(find(c, d, "ntp server 10.10.20.5") + 1, "ntp server 10.10.20.6")
    return [gt(["I5"], [L(d, "ntp server 10.10.20.6")], "iv", "iv01", f"second NTP server added on {d}")]


def iv02(c, r):
    line = "ip route 198.18.0.0 255.254.0.0 198.51.100.1"
    c["rtr-01"].insert(find(c, "rtr-01", "ip route 0.0.0.0 0.0.0.0 198.51.100.1") + 1, line)
    return [gt(["I5"], [L("rtr-01", line)], "iv", "iv02", "static route added on the edge router")]


def iv03(c, r):
    d = r.choice(SW_DEVS)
    i = next(k for k, l in enumerate(c[d]) if l.startswith("snmp-server location "))
    c[d][i] = c[d][i] + "-R2"
    return [gt(["I5"], [L(d, c[d][i])], "iv", "iv03", f"SNMP location string changed on {d}")]


def iv04(c, r):
    p = r.randint(1, 18)
    s, e = block(c, "sw-it-01", gi(p))
    i = s + 1
    c["sw-it-01"][i] = c["sw-it-01"][i] + "-MOVED"
    return [gt(["I5"], [L("sw-it-01", c["sw-it-01"][i]), H("sw-it-01", gi(p))], "iv", "iv04", f"port description changed on sw-it-01 Gi1/0/{p}")]


def iv05(c, r):
    i = find(c, "sw-core-01", "vlan 999")
    c["sw-core-01"][i:i] = ["vlan 40", " name SPARE", "!"]
    return [gt(["I5"], [L("sw-core-01", "vlan 40")], "iv", "iv05", "unused VLAN 40 defined on the core switch")]


def iv06(c, r):
    p = r.choice([21, 22, 23])
    line = replace_in_block(c, "sw-it-01", gi(p), " switchport access vlan 999", " switchport access vlan 30")
    delete_in_block(c, "sw-it-01", gi(p), " shutdown")
    return [gt(["I5"], [L("sw-it-01", line), H("sw-it-01", gi(p))], "iv", "iv06", f"unused IT port Gi1/0/{p} activated in the corporate VLAN")]


def iv07(c, r):
    i = find(c, "fw-01", "logging trap informational")
    c["fw-01"][i] = "logging trap warnings"
    return [gt(["I5"], [L("fw-01", "logging trap warnings")], "iv", "iv07", "firewall logging level changed")]


def iv08(c, r):
    p = r.choice([1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16])
    delete_in_block(c, "sw-ot-01", gi(p), " spanning-tree portfast")
    return [gt(["I5"], [H("sw-ot-01", gi(p))], "iv", "iv08", f"portfast removed from sw-ot-01 Gi1/0/{p}")]


def iv09(c, r):
    line = "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 host 10.10.20.10 eq 8443"
    c["fw-01"].insert(find(c, "fw-01", "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 host 10.10.20.10 eq https") + 1, line)
    return [gt(["I5"], [L("fw-01", line)], "iv", "iv09", "undocumented CORP permit to the historian on tcp/8443")]


def iv10(c, r):
    old = "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 any eq www"
    del c["fw-01"][find(c, "fw-01", old)]
    return [gt(["I5"], [BL("fw-01", old)], "iv", "iv10", "CORP web-browsing permit removed")]


def iv11(c, r):
    d = r.choice(SW_DEVS)
    line = "username vendor2 privilege 1 secret 5 <removed>"
    c[d].insert(find(c, d, "username netadmin privilege 15 secret 5 <removed>") + 1, line)
    return [gt(["I5"], [L(d, line)], "iv", "iv11", f"local user added on {d}")]


FAMILY_IV = [iv01, iv02, iv03, iv04, iv05, iv06, iv07, iv08, iv09, iv10, iv11]


# ---------------------------------------------------------------- compliant set (6 per category)
def c1(c, r, k):
    return []       # only timestamps change (applied by the builder)


def c2(c, r, k):
    opts = [
        ("OT_IN", "access-list OT_IN extended permit tcp host 10.10.10.22 host 10.10.20.10 eq 5450", "before_deny"),
        ("OT_IN", "access-list OT_IN extended permit tcp host 10.10.10.23 host 10.10.20.10 eq 5450", "before_deny"),
        ("CORP_IN", f"access-list CORP_IN extended permit tcp host {r.choice(CORP_HOSTS)} host 10.10.20.10 eq https", "top"),
        ("CORP_IN", f"access-list CORP_IN extended permit tcp host {r.choice(CORP_HOSTS)} host 10.10.20.30 eq 3389", "top"),
        ("OT_IN", f"access-list OT_IN extended permit udp host {r.choice(OT_HOSTS)} host 10.10.20.5 eq ntp", "top"),
        ("MGMT_IN", "access-list MGMT_IN extended permit udp host 10.10.99.50 host 10.10.20.5 eq ntp", "top"),
    ]
    acl, line, where = opts[k]
    ls = acl_lines(c, "fw-01", acl)
    c["fw-01"].insert(ls[0] if where == "top" else ls[-1], line)
    return []


def c3(c, r, k):
    p = r.choice(OT_PORTS)
    opts = [
        ("fw-01", "CORP_IN", f"access-list CORP_IN extended deny tcp 192.168.30.0 255.255.255.0 10.10.10.0 255.255.255.0 eq {p}"),
        ("fw-01", "OUTSIDE_IN", f"access-list OUTSIDE_IN extended deny tcp any 10.10.10.0 255.255.255.0 eq {p}"),
        ("fw-01", "VENDOR_VPN", "access-list VENDOR_VPN extended deny ip 172.16.50.0 255.255.255.0 10.10.10.0 255.255.255.0 log"),
        ("rtr-01", None, " 35 deny   ip any 10.10.0.0 0.0.255.255"),
        ("fw-01", "CORP_IN", f"access-list CORP_IN extended deny ip host {r.choice(CORP_HOSTS)} 10.10.99.0 255.255.255.0"),
        ("fw-01", "DMZ_IN", f"access-list DMZ_IN extended deny tcp any 10.10.10.0 255.255.255.0 eq {p}"),
    ]
    dev, acl, line = opts[k]
    if dev == "rtr-01":
        insert_in_block(c, "rtr-01", "ip access-list extended EDGE_IN", line, after=" 30 deny   ip 192.168.0.0 0.0.255.255 any")
    else:
        c[dev].insert(acl_lines(c, dev, acl)[0], line)
    return []


def c4(c, r, k):
    combos = [(9,), (10,), (11,), (12,), (9, 10), (11, 12)]
    for p in combos[k]:
        insert_in_block(c, "sw-ot-01", gi(p), " shutdown")
    return []


def c5(c, r, k):
    fwl = c["fw-01"]
    if k in (0, 1, 2):
        acl, (a, b) = [("CORP_IN", (0, 1)), ("OT_IN", (0, 1)), ("DMZ_IN", (4, 5))][k]
        ls = acl_lines(c, "fw-01", acl)
        fwl[ls[a]], fwl[ls[b]] = fwl[ls[b]], fwl[ls[a]]
    elif k == 3:
        i = find(c, "rtr-01", " 10 permit 10.10.99.0 0.0.0.255")
        c["rtr-01"][i] = " 15 permit 10.10.99.0 0.0.0.255"
    elif k == 4:
        fwl.insert(acl_lines(c, "fw-01", "CORP_IN")[0], "access-list CORP_IN remark TEMP VENDOR ACCESS CR-2291 REMOVED")
    else:
        s, e = block(c, "sw-ot-01", gi(3))
        c["sw-ot-01"][s + 1] = " description PLC-03 TEMP LAPTOP REMOVED"
    return []


COMPLIANT = [c1, c2, c3, c4, c5]


# ---------------------------------------------------------------- scenarios
def s1(c, r):
    line = "access-list CORP_IN extended permit tcp host 192.168.30.45 host 10.10.10.40 eq 3389"
    c["fw-01"].insert(acl_lines(c, "fw-01", "CORP_IN")[0], line)
    return [gt(["I1"], [L("fw-01", line)], "S1", "s1", "unauthorized IT-to-OT access rule")]


def s2(c, r):
    out = _vlan_change(c, "sw-ot-01", 7, 10, 30, "s2a", "OT-facing access port assigned to the corporate VLAN")
    out += _trunk_change(c, "sw-core-01", 22, "10,99", "10,30,99", "s2b", "permissive trunk towards the OT switch")
    insert_in_block(c, "sw-ot-01", gi(12), " shutdown")
    for g in out:
        g["family"] = "S2"
    return out


def s3(c, r):
    a = "access-list OT_IN extended permit tcp 10.10.10.0 255.255.255.0 any eq https"
    c["fw-01"].insert(find(c, "fw-01", "access-list OT_IN extended deny ip any any log"), a)
    b = "access-list DMZ_IN extended permit ip host 10.10.20.30 10.10.10.0 255.255.255.0"
    c["fw-01"].insert(acl_lines(c, "fw-01", "DMZ_IN")[0], b)
    c["sw-ot-01"].insert(find(c, "sw-ot-01", "logging host 10.10.99.60") + 1, "logging host 192.168.30.77")
    c["sw-core-01"].insert(find(c, "sw-core-01", "snmp-server community <removed> RO SNMP_NMS") + 1, "snmp-server community <removed> RW")
    return [gt(["I2"], [L("fw-01", a)], "S3", "s3a", "permissive ACL entry: OT to any on https"),
            gt(["I2"], [L("fw-01", b)], "S3", "s3b", "permissive ACL entry: jump host to all of OT"),
            gt(["I4"], [L("sw-ot-01", "logging host 192.168.30.77")], "S3", "s3c", "remote logging to a corporate host"),
            gt(["I4"], [L("sw-core-01", "snmp-server community <removed> RW")], "S3", "s3d", "read-write SNMP community")]


# ---------------------------------------------------------------- latent violations (in the approved baseline)
def latent_templates():
    return [i01, i10, i13, (lambda c, r: ii01(c, r, port=4)), ii05,
            (lambda c, r: iii01(c, r, dev="sw-core-01")), (lambda c, r: iii04(c, r, dev="rtr-01")), iii07,
            (lambda c, r: iii10(c, r, dev="sw-it-01")), ii09]


# ---------------------------------------------------------------- resolution of GT specs to anchors
def resolve(gts, base, snap):
    out = []
    for g in gts:
        acc = set()
        for kind, dev, text in g["accept"]:
            src = snap if kind == "line" else base
            idx = [i for i, l in enumerate(src[dev]) if l == text]
            assert idx, (kind, dev, text)
            if kind == "line" and text.startswith(" ") and not text.startswith("interface"):
                # a child line inside a block: anchor the line itself
                acc |= {f"{dev}:{i + 1}" for i in idx}
            elif kind == "line":
                acc |= {f"{dev}:{i + 1}" for i in idx}
            else:
                acc |= {f"{dev}:base:{i + 1}" for i in idx}
        g = dict(g); g["accept"] = sorted(acc)
        out.append(g)
    return out


def changed_devices(base, snap):
    return [d for d in snap if [l for l in snap[d]] != [l for l in base[d]]]


def build(seed=20261103):
    rng = random.Random(seed)
    base = B.baseline(BASE_TS)
    items = []

    def make(set_name, idx, fn, base_cfg=None, latent=False, k=None):
        bcfg = copy.deepcopy(base_cfg or base)
        snap = copy.deepcopy(bcfg)
        g = fn(snap, rng) if k is None else fn(snap, rng, k)
        if latent:
            bcfg = copy.deepcopy(snap)          # the violation is part of the approved baseline
        for d in changed_devices(bcfg, snap) or []:
            touch(snap, d, ts(rng))
        if not changed_devices(bcfg, snap) or set_name in ("compliant_c1", "latent"):
            for d in rng.sample(list(snap), rng.randint(1, 3)):
                touch(snap, d, ts(rng))
        items.append({"set": set_name, "idx": idx, "base": bcfg, "snap": snap, "gt": resolve(g, bcfg, snap)})

    for n, fn in enumerate([s1, s2, s3]):
        make("scenario", n + 1, fn)
    ot_ports = [1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16]
    fam_ii = [partial(ii01, port=p) for p in rng.sample(ot_ports, 3)] + [ii02] + \
             [partial(ii03, port=p) for p in rng.sample(range(1, 19), 2)] + [ii04, ii05, ii06, ii07, ii08, ii09]
    fam_iii = [partial(iii01, dev=d) for d in rng.sample(IOS_DEVS, 2)] + [iii02, iii03] + \
              [partial(iii04, dev=d) for d in rng.sample(IOS_DEVS, 2)] + [iii05, iii06, iii07, iii08, iii09, iii10]
    suite = FAMILY_I + fam_ii + fam_iii + FAMILY_IV
    for n, fn in enumerate(suite):
        make("suite", n + 1, fn)
    for ci, fn in enumerate(COMPLIANT):
        for k in range(6):
            make(f"compliant_c{ci + 1}", k + 1, fn, k=k)
    for n, fn in enumerate(latent_templates()):
        make("latent", n + 1, fn, latent=True)
    return base, items
