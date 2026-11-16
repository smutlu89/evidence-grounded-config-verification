"""Layer 3: deterministic validation gate.

validate(candidates, records, deltas) -> (released, suppressed)

A candidate is released only if
  1. it is well formed and its clarification flag is not set,
  2. every cited anchor exists in the evidence index (records or baseline deltas),
  3. for I1/I2 its zone selectors are registry zone names (the model may name a zone,
     never define its addresses), and
  4. at least one cited anchor is confirmed by the deterministic check for the claimed
     intent, with the same source and destination zones (order-, binding- and
     approved-service-aware for ACLs).
Rejected candidates are never sent back to the model.
"""
from . import checks, site

INTENTS = {"I1", "I2", "I3", "I4", "I5"}
ZONE_NAMES = set(site.ZONES) | {"OUTSIDE", "ANY"}


def _norm_zone(z):
    if not isinstance(z, str):
        return None
    z = z.strip().upper()
    if z in ZONE_NAMES:
        return z
    for name, d in site.ZONES.items():          # an exact registry network is accepted as the zone
        if z == d["net"]:
            return name
    return None


def validate(candidates, records, deltas):
    findings = checks.check(records, deltas)
    by_key = {}
    for f in findings:
        by_key.setdefault((f["intent"], f["anchor"]), []).append(f)
        for rel in f.get("related", []):
            if f["intent"] in ("I4", "I5"):
                by_key.setdefault((f["intent"], rel), []).append(f)
    known = {r["anchor"] for r in records} | {d["anchor"] for d in deltas}
    released, suppressed = [], []
    for c in candidates if isinstance(candidates, list) else []:
        if not isinstance(c, dict):
            suppressed.append({"candidate": c, "reason": "schema_invalid"}); continue
        if c.get("clarification_flag") is True:
            suppressed.append({"candidate": c, "reason": "clarification"}); continue
        intent = str(c.get("intent_id", "")).strip().upper()
        anchors = c.get("anchors") or []
        if isinstance(anchors, str):
            anchors = [anchors]
        if intent not in INTENTS or not anchors:
            suppressed.append({"candidate": c, "reason": "schema_invalid"}); continue
        if any(a not in known for a in anchors):
            suppressed.append({"candidate": c, "reason": "anchor_missing"}); continue
        zones = None
        if intent in ("I1", "I2"):
            zs, zd = _norm_zone(c.get("source_zone")), _norm_zone(c.get("destination_zone"))
            if zs is None or zd is None:
                suppressed.append({"candidate": c, "reason": "selector_invalid"}); continue
            zones = (zs, zd)
        confirmed, zone_mismatch = [], False
        for a in anchors:
            for f in by_key.get((intent, a), []):
                if zones is None or f["zones"] is None or tuple(f["zones"]) == zones or \
                   (zones[1] in ("OUTSIDE", "ANY") and f["zones"][0] == zones[0] and f["zones"][1] in ("OUTSIDE", "ANY", "CORP", "DMZ")):
                    confirmed.append(f)
                else:
                    zone_mismatch = True
        if not confirmed:
            suppressed.append({"candidate": c, "reason": "selector_mismatch" if zone_mismatch else "not_supported"}); continue
        label = "violation" if intent != "I5" else (
            "informational" if all(f["label"] == "informational" for f in confirmed) else "baseline_item")
        released.append({"intent": intent, "anchors": sorted({f["anchor"] for f in confirmed}),
                         "cited": anchors, "zones": zones, "label": label,
                         "claim": c.get("claim", ""), "remediation": c.get("remediation", "")})
    return released, suppressed
