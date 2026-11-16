"""Scoring (PROTOCOL.md section 8).

Decrypts the sealed ground truth, rebuilds every item from the fixed seed, passes every Layer 2 output through
the Layer 3 gate and computes the pre-specified metrics, the comparators and the gate statistics.

Main analysis: the 158 runs of phases 1 and 2 (3 November 2026). Writes run/ground_truth.json, results/runs.json,
results/results.json and results/results.md; these files do not change when phase 3 outputs are present.

Phase 3 (third suite and scenario run, executed on 15 November 2026 after the main analysis was known; see
DEVIATIONS.md item 8) is scored with the same gate and matching rule and reported separately in
results/runs_phase3.json, results/results_phase3.json and results/results_phase3.md.
"""
import difflib
import hashlib
import json
import math
import os
import subprocess
from collections import Counter, defaultdict

from evalkit import checks, delta, gate, gen, parser, validate

ROOT = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(ROOT, "run")
OUT = os.path.join(ROOT, "results")
SEC = {"I1", "I2", "I3", "I4"}
GT_SHA_PREFIX = "2cf6ebcd5321b5e9"          # printed by build_runs.py when the ground truth was sealed


# ------------------------------------------------------------------------------------------------ helpers
def decrypt():
    # the key was held outside the run directory until all runs were complete; a copy is published in run/ground_truth.key.txt
    kf = os.environ.get("EXP_GT_KEY_FILE", "/root/.exp_gt_key")
    if not os.path.exists(kf):
        kf = os.path.join(RUN, "ground_truth.key.txt")
    key = open(kf).read().strip()
    blob = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", "pass:" + key,
                           "-in", os.path.join(RUN, "ground_truth.json.enc")],
                          capture_output=True, check=True).stdout
    return json.loads(blob), hashlib.sha256(blob).hexdigest()


def wilson(k, n, z=1.959964):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def upper_zero(n, alpha=0.05):
    """One-sided upper confidence bound for a proportion when 0 of n events are observed."""
    return {"rule_of_three": 3 / n, "exact": 1 - alpha ** (1 / n)}


def norm_intent(x):
    return str(x or "").strip().upper()


def as_list(a):
    if a is None:
        return []
    return [a] if isinstance(a, str) else [x for x in a if isinstance(x, str)]


def matches(g, intent, anchorset):
    """Does a finding (intent, anchors) match ground-truth item g?  Security items need a security intent,
    baseline-only items (family iv) need I5; in both cases the intent must be in the item's intent set."""
    if intent not in g["intents"]:
        return False
    if g["intents"] == ["I5"]:
        if intent != "I5":
            return False
    elif intent not in SEC:
        return False
    return bool(anchorset & set(g["accept"]))


def scored_gt(item):
    return [g for g in item["gt"]]


def frac(k, n):
    return {"k": k, "n": n, "p": (k / n) if n else None, "ci95": wilson(k, n)}


def pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def fmt(f):
    lo, hi = f["ci95"]
    if f["n"] == 0:
        return "n/a"
    return f"{f['k']}/{f['n']} ({pct(f['p'])}; 95% CI {pct(lo)}–{pct(hi)})"


# ------------------------------------------------------------------------------------------------ main
def main():
    os.makedirs(OUT, exist_ok=True)
    sealed, sha = decrypt()
    assert sha.startswith(GT_SHA_PREFIX), sha
    json.dump(sealed, open(os.path.join(RUN, "ground_truth.json"), "w"), indent=1)

    base, items = gen.build(sealed["seed"])
    by_key = {(it["set"], it["idx"]): it for it in items}
    sid_item = {}
    for sid, meta in sealed["items"].items():
        it = by_key[(meta["set"], meta["idx"])]
        assert it["gt"] == meta["gt"], sid                      # rebuilt items equal the sealed ones
        for dev in it["snap"]:                                  # and equal the dataset files
            assert open(os.path.join(RUN, "dataset", sid, "snapshot", dev + ".cfg")).read() == "\n".join(it["snap"][dev]) + "\n"
            assert open(os.path.join(RUN, "dataset", sid, "baseline", dev + ".cfg")).read() == "\n".join(it["base"][dev]) + "\n"
        sid_item[sid] = it

    phase = {}
    for ph in (1, 2, 3):
        for rid in open(os.path.join(RUN, f"phase{ph}_ids.txt")).read().split():
            phase[rid] = ph

    evid = {}
    for sid, it in sid_item.items():
        recs = parser.parse_all(it["snap"])
        dels = delta.deltas_all(it["base"], it["snap"])
        evid[sid] = (recs, dels)

    # ---------------------------------------------------------------------------------------- per-run scoring
    runs = []
    for rid, meta in sorted(sealed["runs"].items()):
        p = os.path.join(RUN, "outputs", rid + ".json")
        if not os.path.exists(p):
            continue                                            # not executed (compliant runs 2-3, phase 3)
        sid = meta["item"]
        it = sid_item[sid]
        recs, dels = evid[sid]
        try:
            out = json.load(open(p))
            cands = out.get("candidates", [])
            clar = out.get("clarifications", [])
            valid = isinstance(cands, list)
        except Exception:
            cands, clar, valid = [], [], False
        released, suppressed = gate.validate(cands, recs, dels)
        # a released finding is matched to ground truth with the rule of the dataset QA (validate.explain): the
        # anchors it cites, the anchors of the checker findings that confirmed it, and their related anchors
        chk = defaultdict(list)
        for f in checks.check(recs, dels):
            chk[(f["intent"], f["anchor"])].append(f)
        for r in released:
            r["related"] = sorted({x for a in r["anchors"] for f in chk[(r["intent"], a)] for x in f.get("related", [])})
        rel_f = [(r["intent"], set(r["anchors"]) | set(r["cited"]) | set(r["related"])) for r in released]
        gts = scored_gt(it)

        # outcome per ground-truth item: released, suppressed by the gate (with reason), or not proposed
        outcomes = []
        for g in gts:
            if any(matches(g, i, a) for i, a in rel_f):
                outcomes.append("released"); continue
            why = None
            for s in suppressed:
                c = s["candidate"]
                if isinstance(c, dict) and matches(g, norm_intent(c.get("intent_id")), set(as_list(c.get("anchors")))):
                    why = s["reason"]
                    if why != "clarification":
                        break
            outcomes.append(f"suppressed:{why}" if why else "not_proposed")

        # released actionable findings that match no ground-truth item (false alarms)
        false_rel = [r for r in released if r["intent"] in SEC and
                     not any(matches(g, r["intent"], set(r["anchors"]) | set(r["cited"]) | set(r["related"])) for g in gts)]
        # proposed actionable candidates (security intent, no clarification flag) that match no ground-truth item
        prop_act, false_prop = [], []
        for c in cands if isinstance(cands, list) else []:
            if not isinstance(c, dict) or c.get("clarification_flag") is True:
                continue
            i = norm_intent(c.get("intent_id"))
            if i not in SEC:
                continue
            prop_act.append(c)
            if not any(matches(g, i, set(as_list(c.get("anchors")))) for g in gts):
                false_prop.append(c)
        sup_reason = {}
        for s in suppressed:
            sup_reason[id(s["candidate"])] = s["reason"]
        false_prop_reasons = Counter(sup_reason.get(id(c), "released") for c in false_prop)

        runs.append({
            "run": rid, "phase": phase.get(rid), "item": sid, "set": it["set"], "idx": it["idx"],
            "mode": meta["mode"], "question": meta["question"], "rep": meta["run"], "valid_json": valid,
            "n_candidates": len(cands) if isinstance(cands, list) else 0,
            "n_clarification_questions": len(clar) if isinstance(clar, list) else 0,
            "n_flagged": sum(1 for c in cands if isinstance(c, dict) and c.get("clarification_flag") is True) if isinstance(cands, list) else 0,
            "released": [{"intent": r["intent"], "anchors": r["anchors"], "cited": r["cited"], "related": r["related"],
                          "label": r["label"], "zones": r["zones"]} for r in released],
            "suppressed": [{"intent": norm_intent(s["candidate"].get("intent_id")) if isinstance(s["candidate"], dict) else None,
                            "anchors": as_list(s["candidate"].get("anchors")) if isinstance(s["candidate"], dict) else [],
                            "reason": s["reason"]} for s in suppressed],
            "gt": [{"template": g["template"], "family": g["family"], "intents": g["intents"], "desc": g["desc"],
                    "outcome": o} for g, o in zip(gts, outcomes)],
            "false_alarms": len(false_rel),
            "actionable_proposed": len(prop_act),
            "false_proposals": len(false_prop),
            "false_proposal_reasons": dict(false_prop_reasons),
            "false_proposal_examples": [{"intent": norm_intent(c.get("intent_id")), "anchors": as_list(c.get("anchors")),
                                         "claim": c.get("claim", "")} for c in false_prop],
        })
    # main analysis = phases 1 and 2; phase 3 is reported separately (DEVIATIONS.md item 8)
    runs_p3 = [r for r in runs if r["phase"] == 3]
    runs = [r for r in runs if r["phase"] in (1, 2)]
    json.dump(runs, open(os.path.join(OUT, "runs.json"), "w"), indent=1)

    R = {"gt_sha256": sha, "runs_scored": len(runs),
         "runs_by_phase": dict(Counter(r["phase"] for r in runs)),
         "invalid_outputs": sum(1 for r in runs if not r["valid_json"])}
    canon = [r for r in runs if r["mode"] == "canonical"]

    # ---------------------------------------------------------------------------------------- recall
    def gt_table(sets):
        """Per ground-truth item: outcomes across its canonical runs."""
        tab = defaultdict(list)
        for r in canon:
            if r["set"] in sets:
                for k, g in enumerate(r["gt"]):
                    tab[(r["item"], k)].append((r, g))
        return tab

    def recall_block(sets, label):
        tab = gt_table(sets)
        n = len(tab)
        strict = sum(1 for v in tab.values() if all(g["outcome"] == "released" for _, g in v))
        any_ = sum(1 for v in tab.values() if any(g["outcome"] == "released" for _, g in v))
        per_run = defaultdict(lambda: [0, 0])
        for v in tab.values():
            for r, g in v:
                per_run[r["rep"]][1] += 1
                per_run[r["rep"]][0] += g["outcome"] == "released"
        allruns = sum(len(v) for v in tab.values())
        rel_runs = sum(1 for v in tab.values() for _, g in v if g["outcome"] == "released")
        oc = Counter(g["outcome"] for v in tab.values() for _, g in v)
        return {"label": label, "items": n, "strict": frac(strict, n), "any_run": frac(any_, n),
                "per_run": {str(k): frac(*v) for k, v in sorted(per_run.items())},
                "item_runs": frac(rel_runs, allruns), "outcomes_over_item_runs": dict(oc),
                "runs_per_item": dict(Counter(len(v) for v in tab.values()))}

    suite_sets = {"suite"}
    R["recall"] = {"suite": recall_block(suite_sets, "Mutation suite (50 variants)"),
                   "scenarios": recall_block({"scenario"}, "Scenarios S1-S3 (7 scored violations)"),
                   "latent": recall_block({"latent"}, "Latent set (10)")}
    fam = {}
    for f in ("i", "ii", "iii", "iv"):
        tab = defaultdict(list)
        for r in canon:
            if r["set"] == "suite":
                for k, g in enumerate(r["gt"]):
                    if g["family"] == f:
                        tab[(r["item"], k)].append(g["outcome"])
        fam[f] = {"items": len(tab), "strict": frac(sum(all(o == "released" for o in v) for v in tab.values()), len(tab)),
                  "any_run": frac(sum(any(o == "released" for o in v) for v in tab.values()), len(tab)),
                  "item_runs": frac(sum(o == "released" for v in tab.values() for o in v), sum(len(v) for v in tab.values())),
                  "outcomes": dict(Counter(o for v in tab.values() for o in v))}
    R["recall_by_family"] = fam
    sec_tab = defaultdict(list)
    for r in canon:
        if r["set"] == "suite":
            for k, g in enumerate(r["gt"]):
                if g["family"] != "iv":
                    sec_tab[(r["item"], k)].append(g["outcome"])
    R["recall_suite_security"] = {"strict": frac(sum(all(o == "released" for o in v) for v in sec_tab.values()), len(sec_tab)),
                                  "any_run": frac(sum(any(o == "released" for o in v) for v in sec_tab.values()), len(sec_tab))}
    per_template = defaultdict(list)
    for r in canon:
        for g in r["gt"]:
            per_template[(r["set"], g["template"])].append(g["outcome"])
    R["per_template"] = {f"{s}:{t}": dict(Counter(v)) for (s, t), v in sorted(per_template.items())}

    # ---------------------------------------------------------------------------------------- compliant set
    comp = [r for r in canon if r["set"].startswith("compliant")]
    fa_cfg = sum(1 for r in comp if r["false_alarms"] > 0)
    tn = len(comp) - fa_cfg
    ung = sum(1 for r in comp if r["false_proposals"] > 0)
    R["compliant"] = {
        "configs": len(comp), "true_negatives": tn, "specificity": frac(tn, len(comp)),
        "false_alarm_upper_bound_if_zero": upper_zero(len(comp)) if fa_cfg == 0 else None,
        "ungated_configs_with_false_proposal": frac(ung, len(comp)),
        "ungated_specificity": frac(len(comp) - ung, len(comp)),
        "ungated_by_category": {c: frac(sum(1 for r in comp if r["set"] == c and r["false_proposals"] > 0),
                                        sum(1 for r in comp if r["set"] == c)) for c in sorted({r["set"] for r in comp})},
        "i5_released_on_compliant": sum(1 for r in comp for x in r["released"] if x["intent"] == "I5"),
        "i5_informational_on_c4": sum(1 for r in comp if r["set"] == "compliant_c4" for x in r["released"]
                                      if x["intent"] == "I5" and x["label"] == "informational"),
        "configs_with_clarification": sum(1 for r in comp if r["n_flagged"] or r["n_clarification_questions"]),
    }

    # ---------------------------------------------------------------------------------------- precision, F1
    suite_items = R["recall"]["suite"]
    tp = suite_items["strict"]["k"]
    fp_cfg = len({r["item"] for r in canon if (r["set"] == "suite" or r["set"].startswith("compliant")) and r["false_alarms"] > 0})
    prec = tp / (tp + fp_cfg) if tp + fp_cfg else None
    rec = suite_items["strict"]["p"]
    R["config_level"] = {"TP": tp, "FP_configs": fp_cfg, "precision": prec, "recall": rec,
                         "F1": (2 * prec * rec / (prec + rec)) if prec and rec else None}
    # exploratory: the same quantities if every proposed actionable candidate were issued without the gate
    fp_ung = len({r["item"] for r in canon if (r["set"] == "suite" or r["set"].startswith("compliant")) and r["false_proposals"] > 0})
    tab = gt_table({"suite"})
    tp_ung = 0
    for v in tab.values():
        if all(g["outcome"] in ("released",) or g["outcome"].startswith("suppressed:") and g["outcome"] != "suppressed:clarification"
               for _, g in v):
            tp_ung += 1
    p_u = tp_ung / (tp_ung + fp_ung) if tp_ung + fp_ung else None
    r_u = tp_ung / len(tab) if tab else None
    R["config_level_ungated_exploratory"] = {"TP": tp_ung, "FP_configs": fp_ung, "precision": p_u, "recall": r_u,
                                             "F1": (2 * p_u * r_u / (p_u + r_u)) if p_u and r_u else None}
    rel_act = [x for r in canon for x in r["released"] if x["intent"] in SEC]
    R["finding_level_precision"] = frac(len(rel_act) - sum(r["false_alarms"] for r in canon), len(rel_act))
    n_act = sum(r["actionable_proposed"] for r in canon)
    R["finding_level_precision_ungated_exploratory"] = frac(n_act - sum(r["false_proposals"] for r in canon), n_act)

    # ---------------------------------------------------------------------------------------- gate statistics
    allc = sum(r["n_candidates"] for r in runs)
    rel = sum(len(r["released"]) for r in runs)
    reasons = Counter(s["reason"] for r in runs for s in r["suppressed"])
    act = sum(r["actionable_proposed"] for r in canon)
    fprop = sum(r["false_proposals"] for r in canon)
    by_int = defaultdict(Counter)
    for r in runs:
        for x in r["released"]:
            by_int[x["intent"]]["released"] += 1
        for s in r["suppressed"]:
            by_int[s["intent"] or "?"][s["reason"]] += 1
    true_sup = Counter(g["outcome"] for r in canon for g in r["gt"] if g["outcome"].startswith("suppressed:"))
    R["gate"] = {"candidates": allc, "released": rel, "suppressed": sum(reasons.values()), "suppressed_by_reason": dict(reasons),
                 "by_intent": {k: dict(v) for k, v in sorted(by_int.items())},
                 "canonical_actionable_proposed": act, "canonical_false_proposals": frac(fprop, act),
                 "false_proposal_reasons": dict(sum((Counter(r["false_proposal_reasons"]) for r in canon), Counter())),
                 "gt_items_proposed_but_suppressed": dict(true_sup),
                 "runs_with_clarification": frac(sum(1 for r in runs if r["n_flagged"] or r["n_clarification_questions"]), len(runs))}

    # ---------------------------------------------------------------------------------------- comparators
    rule = {"security_detected": 0, "security_total": 0, "i5_detected": 0, "i5_total": 0,
            "latent_detected": 0, "latent_total": 0, "scenario_detected": 0, "scenario_total": 0, "compliant_false_alarm_configs": 0}
    diff = {"raw_flagged": Counter(), "norm_flagged": Counter(), "surfaced": Counter(), "total": Counter()}
    for sid, it in sid_item.items():
        recs, dels = evid[sid]
        f = checks.check(recs, dels)
        missed, unexpl = validate.explain(it, f)
        s = it["set"]
        if s.startswith("compliant"):
            rule["compliant_false_alarm_configs"] += any(x["intent"] in SEC for x in f)
        for g in it["gt"]:
            hit = g not in missed
            key = "latent" if s == "latent" else "scenario" if s == "scenario" else "i5" if g["intents"] == ["I5"] else "security"
            rule[key + "_total"] += 1
            rule[key + "_detected"] += hit
        grp = "compliant" if s.startswith("compliant") else s
        raw_changed = any(it["base"][d] != it["snap"][d] for d in it["snap"])
        diff["raw_flagged"][grp] += raw_changed
        diff["norm_flagged"][grp] += bool(dels)
        diff["total"][grp] += 1
        for g in it["gt"]:
            acc = set(g["accept"])
            surf = any(d["anchor"] in acc or d.get("record") in acc for d in dels)
            diff["surfaced"][grp + "_gt"] += surf
            diff["total"][grp + "_gt"] += 1
            if s == "suite":
                diff["surfaced"]["family_" + g["family"]] += surf
                diff["total"]["family_" + g["family"]] += 1
                if not surf:
                    diff.setdefault("not_surfaced", Counter())[g["template"]] += 1
    R["comparators"] = {"rule_only": rule, "baseline_comparison": {k: dict(v) for k, v in diff.items()}}

    # ---------------------------------------------------------------------------------------- phrasing sub-study
    ph = []
    for r in runs:
        if r["mode"] != "question":
            continue
        o = r["gt"][0]["outcome"]
        if o == "released":
            res = "detected"
        elif r["n_flagged"] or r["n_clarification_questions"]:
            res = "clarification requested"
        else:
            res = "missed"
        if r["false_alarms"]:
            res += " + false release"
        ph.append({"family": r["gt"][0]["family"], "template": r["gt"][0]["template"], "question": r["question"],
                   "outcome": res, "gt_outcome": o, "released_intents": sorted({x["intent"] for x in r["released"]}),
                   "flagged": r["n_flagged"], "questions_asked": r["n_clarification_questions"]})
    R["phrasing"] = sorted(ph, key=lambda x: (x["family"], x["question"]))
    R["phrasing_summary"] = dict(Counter(x["outcome"] for x in ph))
    json.dump(R, open(os.path.join(OUT, "results.json"), "w"), indent=1)
    write_md(R)
    print(open(os.path.join(OUT, "results.md")).read())
    if runs_p3:
        json.dump(runs_p3, open(os.path.join(OUT, "runs_phase3.json"), "w"), indent=1)
        P = phase3_block(canon, runs_p3, sha)
        json.dump(P, open(os.path.join(OUT, "results_phase3.json"), "w"), indent=1)
        write_md_phase3(P)
        print(open(os.path.join(OUT, "results_phase3.md")).read())


# ------------------------------------------------------------------------------------------------ phase 3
def phase3_block(canon12, p3, sha):
    """Third suite and scenario run, reported separately from the main analysis (DEVIATIONS.md item 8).

    canon12: canonical runs of phases 1 and 2 (main analysis); p3: the phase 3 runs."""
    P = {"gt_sha256": sha, "runs_scored": len(p3), "invalid_outputs": sum(1 for r in p3 if not r["valid_json"]),
         "runs_by_set": dict(Counter(r["set"] for r in p3))}

    def third(sets, fam=None):
        k = n = 0
        oc = Counter()
        for r in p3:
            if r["set"] in sets:
                for g in r["gt"]:
                    if fam is None or g["family"] == fam:
                        n += 1
                        k += g["outcome"] == "released"
                        oc[g["outcome"]] += 1
        return {"released": frac(k, n), "outcomes": dict(oc)}

    P["third_run"] = {"suite": third({"suite"}), "scenarios": third({"scenario"}),
                      "suite_security": {"released": frac(sum(third({"suite"}, f)["released"]["k"] for f in ("i", "ii", "iii")),
                                                          sum(third({"suite"}, f)["released"]["n"] for f in ("i", "ii", "iii")))},
                      "by_family": {f: third({"suite"}, f) for f in ("i", "ii", "iii", "iv")}}

    def three(sets, fam=None):
        tab = defaultdict(list)
        for r in list(canon12) + list(p3):
            if r["set"] in sets:
                for k, g in enumerate(r["gt"]):
                    if fam is None or g["family"] == fam or (fam == "sec" and g["family"] != "iv"):
                        tab[(r["item"], k)].append((r["rep"], g["outcome"], g["template"]))
        n = len(tab)
        assert all(sorted(x[0] for x in v) == [1, 2, 3] for v in tab.values())
        strict = sum(all(o == "released" for _, o, _ in v) for v in tab.values())
        any_ = sum(any(o == "released" for _, o, _ in v) for v in tab.values())
        notall = {v[0][2]: {str(rep): o for rep, o, _ in sorted(v)} for v in tab.values() if not all(o == "released" for _, o, _ in v)}
        return {"items": n, "all_three_runs": frac(strict, n), "at_least_one_of_three": frac(any_, n),
                "item_runs": frac(sum(o == "released" for v in tab.values() for _, o, _ in v), sum(len(v) for v in tab.values())),
                "items_not_released_in_every_run": notall}

    P["three_runs"] = {"suite": three({"suite"}), "suite_security": three({"suite"}, "sec"),
                       "by_family": {f: three({"suite"}, f) for f in ("i", "ii", "iii", "iv")},
                       "scenarios": three({"scenario"})}

    reasons = Counter(s["reason"] for r in p3 for s in r["suppressed"])
    by_int = Counter(x["intent"] for r in p3 for x in r["released"])
    act = sum(r["actionable_proposed"] for r in p3)
    fprop = sum(r["false_proposals"] for r in p3)
    rel_act = sum(1 for r in p3 for x in r["released"] if x["intent"] in SEC)
    P["gate"] = {"candidates": sum(r["n_candidates"] for r in p3), "released": sum(len(r["released"]) for r in p3),
                 "suppressed": sum(reasons.values()), "suppressed_by_reason": dict(reasons),
                 "released_by_intent": dict(sorted(by_int.items())),
                 "actionable_proposed": act, "false_proposals": frac(fprop, act),
                 "false_proposals_by_intent": dict(Counter(x["intent"] for r in p3 for x in r["false_proposal_examples"])),
                 "false_proposal_gate_outcome": dict(sum((Counter(r["false_proposal_reasons"]) for r in p3), Counter())),
                 "released_actionable": rel_act, "false_alarms_released": sum(r["false_alarms"] for r in p3),
                 "configs_with_false_proposal": frac(len({r["item"] for r in p3 if r["false_proposals"] > 0}), len({r["item"] for r in p3})),
                 "gt_items_proposed_but_suppressed": dict(Counter(g["outcome"] for r in p3 for g in r["gt"] if g["outcome"].startswith("suppressed:"))),
                 "runs_with_clarification": frac(sum(1 for r in p3 if r["n_flagged"] or r["n_clarification_questions"]), len(p3))}
    return P


def write_md_phase3(P):
    t, a = P["third_run"], P["three_runs"]
    L = ["# Results of phase 3 (third suite and scenario run; reported separately, DEVIATIONS.md item 8)", "",
         f"Ground truth sha256 {P['gt_sha256']}; runs scored {P['runs_scored']} {P['runs_by_set']}; invalid outputs {P['invalid_outputs']}.", "",
         "## Third run alone (released by the gate under the correct intent)", "",
         f"* Mutation suite: {fmt(t['suite']['released'])}; outcomes {t['suite']['outcomes']}",
         f"* Suite, security variants (i–iii): {fmt(t['suite_security']['released'])}"]
    for f, b in t["by_family"].items():
        L.append(f"* Suite family {f}: {fmt(b['released'])}; outcomes {b['outcomes']}")
    L += [f"* Scenario violations: {fmt(t['scenarios']['released'])}; outcomes {t['scenarios']['outcomes']}", "",
          "## Three runs together (phases 1, 2 and 3)", "",
          "| Set | Items | Released in all three runs | Released in at least one | Item-runs |", "|---|---|---|---|---|"]
    rows = [("Mutation suite", a["suite"]), ("Suite, security variants (i–iii)", a["suite_security"])]
    rows += [(f"Suite family {f}", b) for f, b in a["by_family"].items()] + [("Scenario violations", a["scenarios"])]
    for name, b in rows:
        L.append(f"| {name} | {b['items']} | {fmt(b['all_three_runs'])} | {fmt(b['at_least_one_of_three'])} | {fmt(b['item_runs'])} |")
    L += ["", f"Items not released in every run (template: outcome per run): {a['suite']['items_not_released_in_every_run']} "
          f"{a['scenarios']['items_not_released_in_every_run']}", ""]
    g = P["gate"]
    L += ["## Gate, phase 3", "", f"* Candidates {g['candidates']}, released {g['released']} {g['released_by_intent']}, "
          f"suppressed {g['suppressed']}: {g['suppressed_by_reason']}",
          f"* Actionable proposals {g['actionable_proposed']}, matching no ground truth {fmt(g['false_proposals'])} "
          f"{g['false_proposals_by_intent']}; their gate outcome {g['false_proposal_gate_outcome']}",
          f"* Released actionable findings {g['released_actionable']}, of which false {g['false_alarms_released']}",
          f"* Configurations with at least one false actionable proposal {fmt(g['configs_with_false_proposal'])}",
          f"* Ground-truth item-runs proposed but suppressed: {g['gt_items_proposed_but_suppressed']}",
          f"* Runs with a clarification: {fmt(g['runs_with_clarification'])}", ""]
    open(os.path.join(OUT, "results_phase3.md"), "w").write("\n".join(L) + "\n")


def write_md(R):
    L = ["# Results", "", f"Ground truth sha256 {R['gt_sha256']}; runs scored {R['runs_scored']} {R['runs_by_phase']}; "
         f"invalid outputs {R['invalid_outputs']}.", ""]
    L += ["## Recall (released by the gate under the correct intent)", "",
          "| Set | Items | Strict (all runs) | At least one run | Item-runs |", "|---|---|---|---|---|"]
    for k, b in R["recall"].items():
        L.append(f"| {b['label']} | {b['items']} | {fmt(b['strict'])} | {fmt(b['any_run'])} | {fmt(b['item_runs'])} |")
    L.append(f"| Suite, security variants (i–iii) | {R['recall_suite_security']['strict']['n']} | {fmt(R['recall_suite_security']['strict'])} | {fmt(R['recall_suite_security']['any_run'])} | |")
    for f, b in R["recall_by_family"].items():
        L.append(f"| Suite family {f} | {b['items']} | {fmt(b['strict'])} | {fmt(b['any_run'])} | {fmt(b['item_runs'])} |")
    L += ["", "Outcomes over item-runs:", ""]
    for k, b in R["recall"].items():
        L.append(f"* {b['label']}: {b['outcomes_over_item_runs']}; per run {{{', '.join(k2 + ': ' + fmt(v) for k2, v in b['per_run'].items())}}}")
    for f, b in R["recall_by_family"].items():
        L.append(f"* family {f}: {b['outcomes']}")
    c = R["compliant"]
    L += ["", "## Compliant set", "", f"* True negatives {c['true_negatives']}/{c['configs']}; specificity {fmt(c['specificity'])}",
          f"* Upper bound on false-alarm rate (zero observed): {c['false_alarm_upper_bound_if_zero']}",
          f"* Ungated (exploratory): configurations with at least one false actionable proposal {fmt(c['ungated_configs_with_false_proposal'])}; "
          f"by category {{{', '.join(k + ': ' + fmt(v) for k, v in c['ungated_by_category'].items())}}}",
          f"* I5 items released on compliant configurations {c['i5_released_on_compliant']} (informational on C4: {c['i5_informational_on_c4']})",
          f"* Configurations with a clarification {c['configs_with_clarification']}", ""]
    L += ["## Precision and F1", "", f"* Configuration level (gated): {R['config_level']}",
          f"* Configuration level, ungated (exploratory): {R['config_level_ungated_exploratory']}",
          f"* Finding-level precision (gated): {fmt(R['finding_level_precision'])}",
          f"* Finding-level precision, ungated (exploratory): {fmt(R['finding_level_precision_ungated_exploratory'])}", ""]
    g = R["gate"]
    L += ["## Gate", "", f"* Candidates {g['candidates']}, released {g['released']}, suppressed {g['suppressed']}: {g['suppressed_by_reason']}",
          f"* By intent: {g['by_intent']}",
          f"* Canonical runs: actionable proposals {g['canonical_actionable_proposed']}, matching no ground truth {fmt(g['canonical_false_proposals'])}; "
          f"their gate outcome {g['false_proposal_reasons']}",
          f"* Ground-truth item-runs proposed but suppressed: {g['gt_items_proposed_but_suppressed']}",
          f"* Runs with a clarification: {fmt(g['runs_with_clarification'])}", ""]
    L += ["## Comparators", "", f"* Rule-only checker: {R['comparators']['rule_only']}",
          f"* Baseline comparison: {R['comparators']['baseline_comparison']}", ""]
    L += ["## Phrasing sub-study", "", f"Summary {R['phrasing_summary']}", "", "| Family | Question | Outcome | Released intents |", "|---|---|---|---|"]
    for x in R["phrasing"]:
        L.append(f"| {x['family']} ({x['template']}) | {x['question']} | {x['outcome']} | {', '.join(x['released_intents']) or '-'} |")
    L += ["", "## Per template (canonical runs)", ""]
    for k, v in R["per_template"].items():
        L.append(f"* {k}: {v}")
    open(os.path.join(OUT, "results.md"), "w").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
