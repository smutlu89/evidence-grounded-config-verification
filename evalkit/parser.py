"""Layer 1: deterministic evidence extraction for the evaluated Cisco IOS and ASA constructs.

parse(device, lines) -> list of evidence records. Every record carries an anchor
"<device>:<line number>" (1-based, in the snapshot). Comments, descriptions,
remarks, banners and SNMP location/contact strings are never copied into records.
"""
import ipaddress as ipa
import re

ASA = {"fw-01"}

PORTS = {"www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23, "domain": 53, "ntp": 123,
         "snmp": 161, "snmptrap": 162, "ftp": 21, "smtp": 25, "ldap": 389, "bgp": 179, "syslog": 514}

VOLATILE = (re.compile(r"^\s*[!:]"), re.compile(r"^Cryptochecksum:"), re.compile(r"^ntp clock-period"),
            re.compile(r"^Building configuration"), re.compile(r"^Current configuration"))
FREE_TEXT = re.compile(r"^\s*(description|remark|banner|snmp-server location|snmp-server contact)\b|^access-list \S+ remark ")
OUT_OF_SCOPE = re.compile(r"\b(object-group|object|time-range|reflect|evaluate|dynamic)\b")


def is_volatile(line):
    return (not line.strip()) or any(p.search(line) for p in VOLATILE) or line.strip() == "end"


def is_free_text(line):
    return bool(FREE_TEXT.search(line))


def _port(tok):
    return PORTS[tok] if tok in PORTS else int(tok)


def _addr(toks, i, asa):
    """Parse an address spec at toks[i]; return (cidr string, next index) or (None, i) if out of scope."""
    t = toks[i]
    if t in ("any", "any4"):
        return "0.0.0.0/0", i + 1
    if t == "host":
        return f"{toks[i + 1]}/32", i + 2
    if t in ("object", "object-group"):
        return None, i + 2
    # address + mask (ASA) or wildcard (IOS)
    if i + 1 < len(toks) and re.match(r"^\d+\.\d+\.\d+\.\d+$", toks[i + 1]):
        m = toks[i + 1]
        if not asa:
            m = ".".join(str(255 - int(o)) for o in m.split("."))
        return str(ipa.ip_network(f"{t}/{m}", strict=False)), i + 2
    return f"{t}/32", i + 1


def _portspec(toks, i):
    if i < len(toks) and toks[i] in ("eq", "lt", "gt", "range", "neq"):
        op = toks[i]
        if op == "eq":
            p = _port(toks[i + 1]); return [p, p], i + 2
        if op == "range":
            return [_port(toks[i + 1]), _port(toks[i + 2])], i + 3
        if op == "gt":
            return [_port(toks[i + 1]) + 1, 65535], i + 2
        if op == "lt":
            return [0, _port(toks[i + 1]) - 1], i + 2
        return [0, 65535], i + 2          # neq: treated as any (conservative)
    return None, i


def parse_ace(text, asa):
    """Parse '<permit|deny> proto src [port] dst [port] [flags]' or a standard entry."""
    toks = text.split()
    seq = None
    if toks and toks[0].isdigit():
        seq = int(toks[0]); toks = toks[1:]
    action = toks[0]
    rest = toks[1:]
    if OUT_OF_SCOPE.search(" ".join(rest)):
        return {"out_of_scope": True, "action": action, "seq": seq}
    if rest and rest[0] in ("ip", "tcp", "udp", "icmp", "gre", "esp", "ahp"):
        proto = rest[0]
        src, i = _addr(rest, 1, asa)
        sport, i = _portspec(rest, i) if proto in ("tcp", "udp") else (None, i)
        dst, i = _addr(rest, i, asa)
        dport, i = _portspec(rest, i) if proto in ("tcp", "udp") else (None, i)
        flags = [t for t in rest[i:] if t in ("log", "established")]
        rec = {"kind": "extended", "action": action, "proto": proto, "src": src, "dst": dst}
        if sport: rec["src_ports"] = sport
        if dport: rec["dst_ports"] = dport
        if flags: rec["flags"] = flags
    else:  # standard ACL entry
        src, _ = _addr(rest, 0, asa) if rest else ("0.0.0.0/0", 0)
        rec = {"kind": "standard", "action": action, "src": src}
    if seq is not None:
        rec["seq"] = seq
    return rec


def _vlanlist(s):
    out = set()
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-"); out |= set(range(int(a), int(b) + 1))
        elif part.strip():
            out.add(int(part))
    return sorted(out)


def sections(lines):
    """Yield (header_index or None, index) pairs: each line with the index of its top-level parent."""
    parent = None
    for i, l in enumerate(lines):
        if l.startswith(" "):
            yield parent, i
        else:
            parent = i
            yield None, i


def parse(device, lines):
    asa = device in ASA
    recs = []
    anchor = lambda i: f"{device}:{i + 1}"
    acl_pos = {}
    cur = None     # current top-level section context
    iface = None
    vty = None
    for i, raw in enumerate(lines):
        if is_volatile(raw) or is_free_text(raw):
            if not raw.startswith(" "):
                cur = None; iface = None; vty = None
            continue
        line = raw.rstrip()
        top = not line.startswith(" ")
        s = line.strip()
        if top:
            cur = s; iface = None; vty = None
        # ---- ACL entries -------------------------------------------------
        if top and asa and s.startswith("access-list ") and " extended " in s:
            name = s.split()[1]
            body = s.split(" extended ", 1)[1]
            r = parse_ace(body, True)
            pos = acl_pos.get((device, name), 0); acl_pos[(device, name)] = pos + 1
            if r.get("out_of_scope"):
                recs.append({"anchor": anchor(i), "type": "out_of_scope", "device": device, "keyword": "access-list object reference"})
                continue
            recs.append({"anchor": anchor(i), "type": "acl_entry", "device": device, "acl": name, "pos": pos, **r})
            continue
        if top and not asa and re.match(r"^access-list \d+ (permit|deny) ", s):
            name = s.split()[1]
            r = parse_ace(" ".join(s.split()[2:]), False)
            pos = acl_pos.get((device, name), 0); acl_pos[(device, name)] = pos + 1
            recs.append({"anchor": anchor(i), "type": "acl_entry", "device": device, "acl": name, "pos": pos, **r})
            continue
        if top and re.match(r"^ip access-list (standard|extended) ", s):
            cur = ("acl", s.split()[3], s.split()[2])
            continue
        if not top and isinstance(cur, tuple) and cur[0] == "acl":
            r = parse_ace(s, False)
            if r.get("out_of_scope"):
                recs.append({"anchor": anchor(i), "type": "out_of_scope", "device": device, "keyword": "access-list object reference"})
                continue
            pos = acl_pos.get((device, cur[1]), 0); acl_pos[(device, cur[1])] = pos + 1
            recs.append({"anchor": anchor(i), "type": "acl_entry", "device": device, "acl": cur[1], "pos": pos, **r})
            continue
        # ---- ACL bindings --------------------------------------------------
        m = re.match(r"^access-group (\S+) (in|out) interface (\S+)$", s)
        if top and m:
            recs.append({"anchor": anchor(i), "type": "acl_binding", "device": device, "acl": m.group(1),
                         "direction": m.group(2), "interface": m.group(3)})
            continue
        # ---- interfaces ------------------------------------------------------
        if top and s.startswith("interface "):
            iface = {"anchor": anchor(i), "type": "interface", "device": device, "name": s.split(None, 1)[1]}
            recs.append(iface)
            continue
        if not top and iface is not None:
            if s.startswith("switchport access vlan "):
                iface["access_vlan"] = int(s.split()[-1])
            elif s.startswith("switchport mode "):
                iface["mode"] = s.split()[-1]
            elif s.startswith("switchport trunk allowed vlan "):
                v = s.split("allowed vlan ", 1)[1]
                iface["trunk_allowed"] = "all" if v == "all" else _vlanlist(v)
            elif s == "shutdown":
                iface["shutdown"] = True
            elif s.startswith("ip address ") and len(s.split()) >= 4:
                a, m_ = s.split()[2:4]
                iface["ip"] = str(ipa.ip_interface(f"{a}/{m_}"))
            elif s.startswith("ip access-group "):
                _, _, acl, d = s.split()[:4]
                iface[f"acl_{d}"] = acl
                recs.append({"anchor": anchor(i), "type": "acl_binding", "device": device, "acl": acl,
                             "direction": d, "interface": iface["name"]})
            elif s.startswith("nameif "):
                iface["nameif"] = s.split()[1]
            elif s.startswith("security-level "):
                iface["security_level"] = int(s.split()[1])
            elif s.startswith("vlan ") and asa:
                iface["subif_vlan"] = int(s.split()[1])
            elif s.startswith("spanning-tree portfast"):
                iface["portfast"] = True
            continue
        # ---- VLAN database ---------------------------------------------------
        m = re.match(r"^vlan (\d+)$", s)
        if top and m:
            recs.append({"anchor": anchor(i), "type": "vlan", "device": device, "vlan_id": int(m.group(1))})
            continue
        # ---- vty lines -------------------------------------------------------
        if top and s.startswith("line vty "):
            vty = {"anchor": anchor(i), "type": "vty", "device": device, "lines": s[len("line vty "):],
                   "transport_input": [], "access_class": None}
            recs.append(vty)
            continue
        if not top and vty is not None:
            if s.startswith("transport input "):
                vty["transport_input"] = s.split()[2:]
            elif s.startswith("access-class "):
                vty["access_class"] = s.split()[1]
            continue
        # ---- group-policy vpn-filter ------------------------------------------
        if not top and cur and cur.startswith("group-policy ") and s.startswith("vpn-filter value "):
            recs.append({"anchor": anchor(i), "type": "acl_binding", "device": device, "acl": s.split()[-1],
                         "direction": "in", "interface": "vpn-filter (group-policy " + cur.split()[1] + ")"})
            continue
        if not top:
            continue
        # ---- global management-plane statements -------------------------------
        if s in ("ip routing", "no ip routing"):
            recs.append({"anchor": anchor(i), "type": "global", "device": device, "setting": "ip_routing",
                         "enabled": not s.startswith("no ")}); continue
        if s in ("ip http server", "no ip http server", "ip http secure-server", "no ip http secure-server"):
            name = "ip_http_secure_server" if "secure" in s else "ip_http_server"
            recs.append({"anchor": anchor(i), "type": "global", "device": device, "setting": name,
                         "enabled": not s.startswith("no ")}); continue
        if s == "http server enable":
            recs.append({"anchor": anchor(i), "type": "global", "device": device, "setting": "asa_http_server", "enabled": True}); continue
        m = re.match(r"^snmp-server community \S+(?: (RO|RW|ro|rw))?(?: (\S+))?", s)
        if m:
            recs.append({"anchor": anchor(i), "type": "snmp_community", "device": device,
                         "mode": (m.group(1) or "RO").upper(), "acl": m.group(2)}); continue
        m = re.match(r"^snmp-server host (?:(\S+) )?(\d+\.\d+\.\d+\.\d+)", s)
        if m:
            recs.append({"anchor": anchor(i), "type": "snmp_host", "device": device, "address": m.group(2),
                         **({"interface": m.group(1)} if m.group(1) else {})}); continue
        m = re.match(r"^logging host (?:(\S+) )?(\d+\.\d+\.\d+\.\d+)", s)
        if m:
            recs.append({"anchor": anchor(i), "type": "logging_host", "device": device, "address": m.group(2),
                         **({"interface": m.group(1)} if m.group(1) else {})}); continue
        m = re.match(r"^(ssh|http|telnet) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\S+)$", s)
        if m and asa:
            recs.append({"anchor": anchor(i), "type": "mgmt_access", "device": device, "service": m.group(1),
                         "src": str(ipa.ip_network(f"{m.group(2)}/{m.group(3)}", strict=False)), "interface": m.group(4)}); continue
        m = re.match(r"^ntp server (?:vrf \S+ )?(\d+\.\d+\.\d+\.\d+)", s)
        if m:
            recs.append({"anchor": anchor(i), "type": "ntp_server", "device": device, "address": m.group(1)}); continue
        m = re.match(r"^ip route (?:vrf \S+ )?(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\S+)", s)
        if m:
            recs.append({"anchor": anchor(i), "type": "route", "device": device,
                         "prefix": str(ipa.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)), "next_hop": m.group(3)}); continue
        m = re.match(r"^route (\S+) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\S+)", s)
        if m and asa:
            recs.append({"anchor": anchor(i), "type": "route", "device": device, "interface": m.group(1),
                         "prefix": str(ipa.ip_network(f"{m.group(2)}/{m.group(3)}", strict=False)), "next_hop": m.group(4)}); continue
        if OUT_OF_SCOPE.match(s):
            recs.append({"anchor": anchor(i), "type": "out_of_scope", "device": device, "keyword": s.split()[0]})
    return recs


def parse_all(configs):
    out = []
    for dev in sorted(configs):
        out += parse(dev, configs[dev])
    return out
