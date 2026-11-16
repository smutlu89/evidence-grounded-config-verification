"""Layer 1 (continued): line-anchored differences between a snapshot and the approved baseline.

Volatile lines (comments, timestamps, checksums) are ignored. Free-text lines
(descriptions, remarks, banners, SNMP location/contact) are reported as changed
without their content.
"""
import difflib
from .parser import is_volatile, is_free_text, parse


def _keyed(lines):
    out, parent = [], ""
    for i, raw in enumerate(lines):
        if not raw.startswith(" "):
            parent = "" if is_volatile(raw) else raw.strip()
        if is_volatile(raw):
            continue
        sec = parent if raw.startswith(" ") else ""
        out.append((i, sec, raw.rstrip()))
    return out


def _keyword(text):
    s = text.strip()
    if is_free_text(text):
        for k in ("snmp-server location", "snmp-server contact", "description", "remark", "banner"):
            if s.startswith(k) or f" {k} " in f" {s} ":
                return k
        return "free text"
    t = s.split()
    if t and t[0].isdigit():
        t = t[1:]
    if t[:1] == ["access-list"]:
        return "access-list " + (t[1] if len(t) > 1 else "")
    if t[:1] == ["no"]:
        return " ".join(t[:3])
    if t[:1] == ["switchport"]:
        return " ".join(t[:3])
    if t[:1] in (["permit"], ["deny"]):
        return t[0] + " entry"
    return " ".join(t[:2])


def _section_label(sec):
    return "global" if not sec else sec


def deltas(device, base_lines, snap_lines):
    b, s = _keyed(base_lines), _keyed(snap_lines)
    bk = [(sec, txt) for _, sec, txt in b]
    sk = [(sec, txt) for _, sec, txt in s]
    snap_recs = {r["anchor"]: r for r in parse(device, snap_lines)}
    base_recs = {r["anchor"]: r for r in parse(device, base_lines)}

    def rec_for(lines, recs, idx, prefix=""):
        a = f"{device}:{idx + 1}"
        if a in recs:
            return a
        j = idx
        while j > 0 and lines[j].startswith(" "):
            j -= 1
        a = f"{device}:{j + 1}"
        return a if a in recs else None

    def strip(r):
        return {k: v for k, v in r.items() if k not in ("anchor", "device")} if r else None

    raw = []
    sm = difflib.SequenceMatcher(None, bk, sk, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            continue
        dels = list(range(i1, i2)); ins = list(range(j1, j2))
        if op == "replace":
            n = min(len(dels), len(ins))
            for a, c in zip(dels[:n], ins[:n]):
                raw.append(("modified", a, c))
            dels, ins = dels[n:], ins[n:]
        raw += [("removed", a, None) for a in dels] + [("added", None, c) for c in ins]
    # moved entries: same text removed in one place and added in another
    removed = {(bk[a]): a for ch, a, c in raw if ch == "removed"}
    out, used = [], set()
    for ch, a, c in raw:
        if ch == "added" and sk[c] in removed and removed[sk[c]] not in used:
            used.add(removed[sk[c]])
            out.append(("moved", removed[sk[c]], c))
        elif ch == "removed":
            continue
        else:
            out.append((ch, a, c))
    out += [("removed", a, None) for ch, a, c in raw if ch == "removed" and a not in used]

    recs = []
    for ch, a, c in out:
        if c is not None:
            idx = s[c][0]; sec = s[c][1]; txt = s[c][2]
            anchor = f"{device}:{idx + 1}"
            rec_anchor = rec_for(snap_lines, snap_recs, idx)
        else:
            idx = b[a][0]; sec = b[a][1]; txt = b[a][2]
            anchor = f"{device}:base:{idx + 1}"
            rec_anchor = None
            if sec and sec in snap_lines:          # the enclosing section still exists in the snapshot
                h = f"{device}:{snap_lines.index(sec) + 1}"
                rec_anchor = h if h in snap_recs else None
        d = {"anchor": anchor, "type": "baseline_delta", "device": device, "change": ch,
             "section": _section_label(sec) if not is_free_text(sec or "x") else "free-text section",
             "keyword": _keyword(txt)}
        if is_free_text(txt):
            d["free_text"] = True
        if rec_anchor:
            d["record"] = rec_anchor
        if a is not None:
            bidx = b[a][0]
            d["baseline_anchor"] = f"{device}:base:{bidx + 1}"
            br = base_recs.get(rec_for(base_lines, base_recs, bidx) or "")
            if br and ch in ("removed", "modified"):
                d["baseline_record"] = strip(br)
        recs.append(d)
    return recs


def deltas_all(base, snap):
    out = []
    for dev in sorted(snap):
        out += deltas(dev, base[dev], snap[dev])
    return out
