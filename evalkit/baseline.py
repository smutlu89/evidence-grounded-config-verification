"""Approved baseline configurations for the five devices of the synthetic topology.

Each function returns the configuration as a list of lines. Secrets and SNMP
community strings appear as <removed>, as they would after sanitization.
"""

OT_PORTS = {1: "PLC-01", 2: "PLC-02", 3: "PLC-03", 4: "PLC-04", 5: "RTU-01", 6: "RTU-02",
            7: "HMI-01", 8: "HMI-02", 9: "PLC-U2-01", 10: "PLC-U2-02", 11: "HMI-U2-01",
            12: "RTU-U2-01", 13: "SCADA-SRV-01", 14: "SCADA-SRV-02", 15: "EWS-01", 16: "PROT-RELAY-GW"}
CORE_PORTS = {1: "HISTORIAN-01", 2: "NTP-SRV-01", 3: "JUMP-HOST-01", 4: "PATCH-SRV-01"}


def _ios_head(host, ts, version="15.2"):
    return ["!", f"! Last configuration change at {ts} by netadmin", "!", f"version {version}",
            "no service pad", "service timestamps debug datetime msec", "service timestamps log datetime msec",
            "service password-encryption", "!", f"hostname {host}", "!", "boot-start-marker", "boot-end-marker", "!",
            "enable secret 5 <removed>", "!", "username netadmin privilege 15 secret 5 <removed>", "aaa new-model", "!",
            "aaa authentication login default local", "aaa authorization exec default local", "!", "aaa session-id common",
            "switch 1 provision ws-c3750x-24t", "system mtu routing 1500", "ip domain-name plant.local", "no ip domain-lookup",
            "!", "spanning-tree mode rapid-pvst", "spanning-tree extend system-id", "!",
            "vlan internal allocation policy ascending", "!"]


def _vlans(ids):
    names = {10: "OT_CONTROL", 20: "DMZ", 30: "CORP", 99: "MGMT", 999: "PARKING"}
    out = []
    for v in ids:
        out += [f"vlan {v}", f" name {names[v]}", "!"]
    return out


def _access(n, desc, vlan, shut=False, portfast=True):
    out = [f"interface GigabitEthernet1/0/{n}", f" description {desc}", f" switchport access vlan {vlan}",
           " switchport mode access"]
    if portfast and not shut:
        out.append(" spanning-tree portfast")
    if shut:
        out.append(" shutdown")
    return out + ["!"]


def _trunk(n, desc, allowed):
    return [f"interface GigabitEthernet1/0/{n}", f" description {desc}", " switchport trunk encapsulation dot1q",
            f" switchport trunk allowed vlan {allowed}", " switchport mode trunk", "!"]


def _ios_tail(mgmt_ip, location):
    return ["interface Vlan1", " no ip address", " shutdown", "!", "interface Vlan99",
            f" ip address {mgmt_ip} 255.255.255.0", "!", "ip default-gateway 10.10.99.1", "no ip http server",
            "no ip http secure-server", "!", "ip access-list standard SNMP_NMS", " permit 10.10.99.50", " deny   any log",
            "ip access-list standard VTY_MGMT", " permit 10.10.99.0 0.0.0.255", " deny   any log", "!",
            "logging host 10.10.99.60", "snmp-server community <removed> RO SNMP_NMS", f"snmp-server location {location}",
            "snmp-server host 10.10.99.50 version 2c <removed>", "!", "line con 0", "line vty 0 4",
            " access-class VTY_MGMT in", " transport input ssh", "line vty 5 15", " access-class VTY_MGMT in",
            " transport input ssh", "!", "ntp server 10.10.20.5", "end"]


def sw_ot(ts):
    out = _ios_head("sw-ot-01", ts) + _vlans([10, 99, 999])
    for n in range(1, 17):
        out += _access(n, OT_PORTS[n], 10)
    for n in range(17, 24):
        out += _access(n, "UNUSED", 999, shut=True)
    out += _trunk(24, "UPLINK-SW-CORE-01", "10,99")
    return out + _ios_tail("10.10.99.11", "PLANT-CONTROL-ROOM")


def sw_it(ts):
    out = _ios_head("sw-it-01", ts) + _vlans([30, 99, 999])
    for n in range(1, 21):
        desc = "REPORT-SRV-01" if n == 20 else ("PRINTER-01" if n == 19 else f"OFFICE-PC-{n:02d}")
        out += _access(n, desc, 30)
    for n in range(21, 24):
        out += _access(n, "UNUSED", 999, shut=True)
    out += _trunk(24, "UPLINK-SW-CORE-01", "30,99")
    return out + _ios_tail("10.10.99.13", "PLANT-ADMIN-BUILDING")


def sw_core(ts):
    out = _ios_head("sw-core-01", ts) + _vlans([10, 20, 30, 99, 999])
    for n in range(1, 5):
        out += _access(n, CORE_PORTS[n], 20)
    for n in list(range(5, 21)):
        out += _access(n, "UNUSED", 999, shut=True)
    out += _trunk(21, "TRUNK-SW-IT-01", "30,99")
    out += _trunk(22, "TRUNK-SW-OT-01", "10,99")
    out += _access(23, "UNUSED", 999, shut=True)
    out += _trunk(24, "TRUNK-FW-01", "10,20,30,99")
    return out + _ios_tail("10.10.99.10", "PLANT-DMZ-RACK")


def fw(ts):
    return [
        ": Saved", ":", ": Serial Number: <removed>",
        ": Hardware:   ASA5516, 8192 MB RAM, CPU Atom C2000 series 2416 MHz, 1 CPU (8 cores)",
        f": Written by netadmin at {ts}", "!", "ASA Version 9.8(4)20", "!", "hostname fw-01", "domain-name plant.local",
        "enable password <removed> encrypted", "names", "no mac-address auto", "!",
        "interface GigabitEthernet1/1", " nameif outside", " security-level 0", " ip address 203.0.113.2 255.255.255.248", "!",
        "interface GigabitEthernet1/2", " no nameif", " no security-level", " no ip address", "!",
        "interface GigabitEthernet1/2.10", " vlan 10", " nameif ot", " security-level 100", " ip address 10.10.10.1 255.255.255.0", "!",
        "interface GigabitEthernet1/2.20", " vlan 20", " nameif dmz", " security-level 50", " ip address 10.10.20.1 255.255.255.0", "!",
        "interface GigabitEthernet1/2.30", " vlan 30", " nameif corp", " security-level 80", " ip address 192.168.30.1 255.255.255.0", "!",
        "interface GigabitEthernet1/2.99", " vlan 99", " nameif mgmt", " security-level 100", " ip address 10.10.99.1 255.255.255.0", "!",
        "interface Management1/1", " management-only", " shutdown", " no nameif", " no security-level", " no ip address", "!",
        "ftp mode passive", "dns server-group DefaultDNS", " domain-name plant.local",
        "access-list OUTSIDE_IN extended deny ip any any log",
        "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 host 10.10.20.10 eq https",
        "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 host 10.10.20.30 eq 3389",
        "access-list CORP_IN extended deny ip 192.168.30.0 255.255.255.0 10.10.10.0 255.255.255.0 log",
        "access-list CORP_IN extended deny ip 192.168.30.0 255.255.255.0 10.10.99.0 255.255.255.0 log",
        "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 any eq https",
        "access-list CORP_IN extended permit tcp 192.168.30.0 255.255.255.0 any eq www",
        "access-list CORP_IN extended permit udp 192.168.30.0 255.255.255.0 any eq domain",
        "access-list CORP_IN extended deny ip any any log",
        "access-list DMZ_IN extended permit tcp host 10.10.20.10 host 192.168.30.20 eq https",
        "access-list DMZ_IN extended permit tcp host 10.10.20.30 host 10.10.10.40 eq 3389",
        "access-list DMZ_IN extended deny ip any 10.10.10.0 255.255.255.0 log",
        "access-list DMZ_IN extended deny ip any 10.10.99.0 255.255.255.0 log",
        "access-list DMZ_IN extended permit udp host 10.10.20.5 any eq ntp",
        "access-list DMZ_IN extended permit tcp host 10.10.20.40 any eq https",
        "access-list DMZ_IN extended deny ip any any log",
        "access-list OT_IN extended permit tcp host 10.10.10.20 host 10.10.20.10 eq 5450",
        "access-list OT_IN extended permit tcp host 10.10.10.21 host 10.10.20.10 eq 5450",
        "access-list OT_IN extended permit udp 10.10.10.0 255.255.255.0 host 10.10.20.5 eq ntp",
        "access-list OT_IN extended permit tcp 10.10.10.0 255.255.255.0 host 10.10.20.40 eq 8530",
        "access-list OT_IN extended deny ip any any log",
        "access-list MGMT_IN extended permit udp 10.10.99.0 255.255.255.0 host 10.10.20.5 eq ntp",
        "access-list MGMT_IN extended deny ip any any log",
        "access-list VENDOR_VPN extended permit tcp 172.16.50.0 255.255.255.0 host 10.10.20.30 eq 3389",
        "access-list VENDOR_VPN extended deny ip any any log",
        "pager lines 24", "logging enable", "logging timestamp", "logging trap informational", "logging host mgmt 10.10.99.60",
        "mtu outside 1500", "mtu ot 1500", "mtu dmz 1500", "mtu corp 1500", "mtu mgmt 1500",
        "ip local pool VENDOR_POOL 172.16.50.10-172.16.50.50 mask 255.255.255.0",
        "icmp unreachable rate-limit 1 burst-size 1", "no asdm history enable", "arp timeout 14400",
        "no arp permit-nonconnected",
        "access-group OUTSIDE_IN in interface outside", "access-group OT_IN in interface ot",
        "access-group DMZ_IN in interface dmz", "access-group CORP_IN in interface corp",
        "access-group MGMT_IN in interface mgmt",
        "route outside 0.0.0.0 0.0.0.0 203.0.113.1 1",
        "timeout xlate 3:00:00", "timeout conn 1:00:00 half-closed 0:10:00 udp 0:02:00 sctp 0:02:00 icmp 0:00:02",
        "user-identity default-domain LOCAL", "aaa authentication ssh console LOCAL",
        "http server enable", "http 10.10.99.0 255.255.255.0 mgmt",
        "snmp-server host mgmt 10.10.99.50 community <removed> version 2c", "snmp-server location PLANT-DMZ-RACK",
        "no snmp-server contact", "snmp-server enable traps snmp authentication linkup linkdown coldstart warmstart",
        "crypto ipsec security-association pmtu-aging infinite", "telnet timeout 5", "ssh stricthostkeycheck",
        "ssh 10.10.99.0 255.255.255.0 mgmt", "ssh timeout 10", "ssh version 2", "ssh key-exchange group dh-group14-sha1",
        "console timeout 0", "threat-detection basic-threat", "threat-detection statistics access-list",
        "ntp server 10.10.20.5", "webvpn", " enable outside", " anyconnect enable", " tunnel-group-list enable",
        "group-policy VENDOR internal", "group-policy VENDOR attributes", " vpn-filter value VENDOR_VPN",
        " vpn-tunnel-protocol ssl-client", "username netadmin password <removed> encrypted privilege 15",
        "tunnel-group VENDOR-TG type remote-access", "tunnel-group VENDOR-TG general-attributes",
        " address-pool VENDOR_POOL", " default-group-policy VENDOR", "!", "class-map inspection_default",
        " match default-inspection-traffic", "!", "policy-map global_policy", " class inspection_default",
        "  inspect dns", "  inspect ftp", "  inspect icmp", "!", "service-policy global_policy global",
        "prompt hostname context", "Cryptochecksum:<removed>", ": end",
    ]


def rtr(ts):
    return [
        "!", f"! Last configuration change at {ts} by netadmin", "!", "version 16.9",
        "service timestamps debug datetime msec", "service timestamps log datetime msec", "service password-encryption",
        "platform qfp utilization monitor load 80", "no platform punt-keepalive disable-kernel-core", "!",
        "hostname rtr-01", "!", "boot-start-marker", "boot-end-marker", "!", "vrf definition Mgmt-intf", " !",
        " address-family ipv4", " exit-address-family", "!", "enable secret 5 <removed>", "!", "aaa new-model",
        "aaa authentication login default local", "aaa authorization exec default local", "aaa session-id common", "!",
        "ip domain name plant.local", "no ip domain lookup", "!", "login on-success log", "!",
        "username netadmin privilege 15 secret 5 <removed>", "!",
        "interface GigabitEthernet0/0/0", " description ISP-UPLINK", " ip address 198.51.100.2 255.255.255.252",
        " ip access-group EDGE_IN in", " negotiation auto", "!",
        "interface GigabitEthernet0/0/1", " description TO-FW-01-OUTSIDE", " ip address 203.0.113.1 255.255.255.248",
        " negotiation auto", "!",
        "interface GigabitEthernet0", " vrf forwarding Mgmt-intf", " ip address 10.10.99.12 255.255.255.0",
        " negotiation auto", "!",
        "ip forward-protocol nd", "no ip http server", "no ip http secure-server",
        "ip route 0.0.0.0 0.0.0.0 198.51.100.1", "ip route vrf Mgmt-intf 0.0.0.0 0.0.0.0 10.10.99.1", "!",
        "ip access-list standard SNMP_NMS", " 10 permit 10.10.99.50", " 20 deny   any log",
        "ip access-list standard VTY_MGMT", " 10 permit 10.10.99.0 0.0.0.255", " 20 deny   any log", "!",
        "ip access-list extended EDGE_IN", " 10 deny   ip 10.0.0.0 0.255.255.255 any",
        " 20 deny   ip 172.16.0.0 0.15.255.255 any", " 30 deny   ip 192.168.0.0 0.0.255.255 any",
        " 40 permit tcp any host 203.0.113.2 eq 443", " 50 permit udp any host 203.0.113.2 eq 443",
        " 60 permit tcp any 203.0.113.0 0.0.0.7 established", " 70 permit udp any eq domain 203.0.113.0 0.0.0.7",
        " 80 permit udp any eq ntp host 203.0.113.2", " 90 deny   ip any any log", "!",
        "logging host 10.10.99.60 vrf Mgmt-intf", "snmp-server community <removed> RO SNMP_NMS",
        "snmp-server location PLANT-EDGE", "snmp-server host 10.10.99.50 vrf Mgmt-intf version 2c <removed>", "!",
        "control-plane", "!", "line con 0", " transport input none", " stopbits 1", "line aux 0", " stopbits 1",
        "line vty 0 4", " access-class VTY_MGMT in vrf-also", " transport input ssh",
        "line vty 5 15", " access-class VTY_MGMT in vrf-also", " transport input ssh", "!",
        "ntp server vrf Mgmt-intf 10.10.20.5", "!", "end",
    ]


DEVICES = ["fw-01", "rtr-01", "sw-core-01", "sw-ot-01", "sw-it-01"]


def baseline(ts="09:14:22 UTC Mon Oct 5 2026"):
    return {"fw-01": fw(ts.replace(" UTC", ".051 UTC")), "rtr-01": rtr(ts), "sw-core-01": sw_core(ts),
            "sw-ot-01": sw_ot(ts), "sw-it-01": sw_it(ts)}
