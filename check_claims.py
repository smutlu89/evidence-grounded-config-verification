"""Cross-check every quantitative claim of the chapter (content.txt and build.js tables) against the results."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
CH = sys.argv[1] if len(sys.argv) > 1 else "/home/claude/chapter11/v5"
R = json.load(open(os.path.join(ROOT, "results", "results.json")))
CT = json.load(open(os.path.join(ROOT, "results", "clarification_topics.json")))
runs = json.load(open(os.path.join(ROOT, "results", "runs.json")))
text = open(os.path.join(CH, "content.txt")).read()
tables = open(os.path.join(CH, "build.js")).read()
both = text + tables


def p1(x):
    return f"{100 * x:.1f}%"


def ci(f):
    lo, hi = f["ci95"]
    return f"{100 * lo:.1f}–{100 * hi:.1f}%".replace("100.0%", "100%")


fails = 0


def check(desc, cond, *snippets, where=both):
    global fails
    miss = [s for s in snippets if s not in where]
    ok = bool(cond) and not miss
    fails += not ok
    print(("OK   " if ok else "FAIL ") + desc + (f"  missing: {miss}" if miss else "") + ("" if cond else "  (value mismatch)"))


S = R["recall"]["suite"]; SC = R["recall"]["scenarios"]; LA = R["recall"]["latent"]; SEC = R["recall_suite_security"]
FAM = R["recall_by_family"]; C = R["compliant"]; G = R["gate"]; CL = R["config_level"]; CU = R["config_level_ungated_exploratory"]
BC = R["comparators"]["baseline_comparison"]; RO = R["comparators"]["rule_only"]

check("suite strict 49/50", S["strict"]["k"] == 49 and S["strict"]["n"] == 50, "49 of the 50 suite variants in both runs", "49/50 = 98.0%")
check("suite strict CI", ci(S["strict"]) == "89.5–99.6%", "89.5–99.6%")
check("suite any run 50/50", S["any_run"]["k"] == 50, "all 50 in at least one run", "50/50 = 100% [92.9–100%]")
check("any-run CI", ci(S["any_run"]) == "92.9–100%")
check("security 39/39 both runs", SEC["strict"]["k"] == 39 == SEC["strict"]["n"], "All 39 security variants", "39/39 [91.0–100%]", "lower bound of 91.0%")
check("security CI", ci(SEC["strict"]) == "91.0–100%")
check("family i-iv strict", (FAM["i"]["strict"]["k"], FAM["ii"]["strict"]["k"], FAM["iii"]["strict"]["k"], FAM["iv"]["strict"]["k"]) == (15, 12, 12, 10)
      and FAM["iv"]["any_run"]["k"] == 11, '"Suite (iv) Baseline-only deltas (11)", "10/11", "11/11", "11/11", "11/11"', '"Suite (i) ACL permutations (15)", "15/15", "15/15", "15/15", "13/15 (a)"')
check("scenarios 7/7 both runs", SC["strict"]["k"] == 7 == SC["strict"]["n"], "All seven scenario violations were released in both runs", "7/7 [64.6–100%]")
check("scenario CI", ci(SC["strict"]) == "64.6–100%")
check("latent 10/10", LA["strict"]["k"] == 10 == LA["strict"]["n"], "All ten latent violations were found", "10/10 [72.2–100%]")
check("latent CI", ci(LA["strict"]) == "72.2–100%")
check("only strict miss iv01 (clarification)", R["per_template"]["suite:iv01"] == {"released": 1, "suppressed:clarification": 1}
      and sum(1 for k, v in R["per_template"].items() if k.startswith("suite:") and set(v) != {"released"}) == 1, "Variant iv01 adds a second NTP server")
check("rule-only perfect", RO["security_detected"] == RO["security_total"] == 39 and RO["i5_detected"] == 11 and RO["latent_detected"] == 10
      and RO["scenario_detected"] == 7 and RO["compliant_false_alarm_configs"] == 0, '"Suite total (50)", "49/50 = 98.0% [89.5–99.6%]", "50/50 = 100% [92.9–100%]", "50/50", "48/50"', '"Latent set (10)", "10/10 [72.2–100%]", "–", "10/10", "0/10 (b)"', '"0/30 (c)", "–", "0/30", "24/30 (d)"')
check("normalized comparison lists change 48/50, fam i 13/15, latent 0/10, scenarios 7/7",
      BC["surfaced"]["suite_gt"] == 48 and BC["surfaced"]["family_i"] == 13 and BC["surfaced"]["latent_gt"] == 0 and BC["surfaced"]["scenario_gt"] == 7
      and BC["not_surfaced"] == {"i03": 1, "i04": 1}, "13/15 (a)", "48/50", "37/39", "0/10 (b)")
check("normalized flags 24/30 compliant, raw 30/30 and 10/10 latent", BC["norm_flagged"]["compliant"] == 24 and BC["raw_flagged"]["compliant"] == 30
      and BC["raw_flagged"]["latent"] == 10 and BC["norm_flagged"]["latent"] == 0, "24 of the 30 compliant configurations", "24/30 (d)", "flags 30 of 30")
check("compliant: 0 false alarms, specificity 30/30", C["true_negatives"] == 30 and C["configs"] == 30, "specificity of 30/30", "30/30 = 100% [88.6–100%]")
check("specificity CI", ci(C["specificity"]) == "88.6–100%")
check("upper bound 9.5% exact, 10% rule of three", abs(C["false_alarm_upper_bound_if_zero"]["exact"] - 0.095) < 0.0005, "9.5%", "10% by the rule of three")
check("ungated compliant 5/30 16.7% [7.3–33.6%]", C["ungated_configs_with_false_proposal"]["k"] == 5 and ci(C["ungated_configs_with_false_proposal"]) == "7.3–33.6%",
      "In 5 of the 30 compliant configurations (16.7%; 95% interval 7.3–33.6%)", "5/30 = 16.7% [7.3–33.6%]", "25/30 = 83.3%")
cat = {k: v["k"] for k, v in C["ungated_by_category"].items()}
check("ungated by category", cat == {"compliant_c1": 1, "compliant_c2": 2, "compliant_c3": 0, "compliant_c4": 1, "compliant_c5": 1}, "C1 1/6, C2 2/6, C3 0/6, C4 1/6, C5 1/6")
check("26 I5 items on compliant, 8 informational", C["i5_released_on_compliant"] == 26 and C["i5_informational_on_c4"] == 8, "26 baseline-consistency items", "the eight that concerned authorized shutdowns", "26 (8 informational, all in C4)")
check("C1 produced no item", all(not r["released"] for r in runs if r["set"] == "compliant_c1"), "The timestamp-only configurations produced no item at all")
check("gate 339/310/29, 17 not supported, 12 clarification, 0 other", G["candidates"] == 339 and G["released"] == 310 and G["suppressed"] == 29
      and G["suppressed_by_reason"] == {"clarification": 12, "not_supported": 17}, "proposed 339 candidates", "The gate released 310 and suppressed 29", "Twelve of the suppressed", "the other 17")
check("released by intent", {k: v.get("released", 0) for k, v in G["by_intent"].items()} == {"I1": 36, "I2": 52, "I3": 34, "I4": 35, "I5": 153}, "I5 153, I2 52, I1 36, I4 35, I3 34")
check("mean candidates 2.1", round(G["candidates"] / R["runs_scored"], 1) == 2.1, "2.1 per run on average")
check("false proposals 17/162 10.5% [6.7–16.2%]", G["canonical_false_proposals"]["k"] == 17 and G["canonical_actionable_proposed"] == 162
      and ci(G["canonical_false_proposals"]) == "6.7–16.2%", "17 of 162 proposed actionable findings (10.5%; 95% interval 6.7–16.2%)", "(10.5% of 162)")
check("all 145 true released", R["finding_level_precision"]["k"] == 145 == R["finding_level_precision"]["n"], "releasing all 145", "145/145 = 100% [97.4–100%]")
check("ungated finding precision 145/162 89.5% [83.8–93.3%]", R["finding_level_precision_ungated_exploratory"]["k"] == 145
      and ci(R["finding_level_precision_ungated_exploratory"]) == "83.8–93.3%", "145/162 = 89.5% [83.8–93.3%]", "from 100% to 89.5%")
check("config precision 1.00 vs 0.79; F1 0.99 vs 0.87", CL["TP"] == 49 and CL["FP_configs"] == 0 and round(CU["precision"], 2) == 0.79
      and round(CL["F1"], 2) == 0.99 and round(CU["F1"], 2) == 0.87 and CU["TP"] == 49 and CU["FP_configs"] == 13,
      "from 1.00 to 0.79", "F1 from 0.99 to 0.87", "49/49 = 1.00", "49/62 = 0.79")
fp = [x for r in runs for x in r["false_proposal_examples"]]
check("13 I4 + 4 I2 false proposals", sum(x["intent"] == "I4" for x in fp) == 13 and sum(x["intent"] == "I2" for x in fp) == 4, "Thirteen claimed", "The other four claimed", "13 under I4, 4 under I2")
check("no correct finding suppressed except one flagged", G["gt_items_proposed_but_suppressed"] == {"suppressed:clarification": 1}, "one was a correct I5 finding")
check("runs with clarification 50/158 31.6%", G["runs_with_clarification"]["k"] == 50 and CT["runs_with_clarification"] == 50, "Fifty of the 158 runs (31.6%)", "50/158 = 31.6%")
t = CT["runs_per_topic"]; vals = sorted(t.values(), reverse=True)
check("clarification topics 25/22/14/3/2/1", vals == [25, 22, 14, 3, 2, 1], "in 25 runs", "(22 runs)", "(14 runs;", "were active (3)", "approved (2)", "interfaces (1)")
check("phrasing 11/12", R["phrasing_summary"] == {"detected": 11, "missed": 1}, "11 of the 12 colloquial questions", "11 of 12 colloquial questions")
miss = [x for x in R["phrasing"] if x["outcome"] == "missed"][0]
check("phrasing miss is i07 office question", miss["template"] == "i07" and miss["question"].startswith("Can anyone on the office network"), "'Can anyone on the office network get into the control system?'")
check("runs 105 + 53 = 158", R["runs_by_phase"] == {"1": 105, "2": 53} or R["runs_by_phase"] == {1: 105, 2: 53}, "(105 runs)", "(53 runs)", "158 runs")
check("all outputs valid", R["invalid_outputs"] == 0, "All 158 outputs were valid JSON")

# dataset facts
sys.path.insert(0, ROOT)
from evalkit import gen, parser  # noqa: E402
base, items = gen.build()
check("911 lines, 197 records", sum(len(v) for v in base.values()) == 911 and len(parser.parse_all(base)) == 197, "911 configuration lines", "197 evidence records")
check("93 items", len(items) == 93, "All 93 items passed", '"93"')
sizes = [os.path.getsize(os.path.join(ROOT, "run", "prompts", f)) for f in os.listdir(os.path.join(ROOT, "run", "prompts"))]
check("prompt about 30 kB", 29000 < min(sizes) and max(sizes) < 32000, "about 30 kB")
check("abstract < 150 words", len(text.split("#1 Abstract")[1].split("**Keywords")[0].split()) < 150)

# ---- revision of 16 November 2026: definitions, clarification channels, market example, third run
canon = [r for r in runs if r["mode"] == "canonical"]
quest = [r for r in runs if r["mode"] == "question"]
check("146 canonical runs; question runs: 17 candidates, all released, no unsupported proposal",
      len(canon) == 146 and len(quest) == 12 and sum(r["n_candidates"] for r in quest) == 17
      and sum(len(r["released"]) for r in quest) == 17 and sum(r["false_proposals"] for r in quest) == 0
      and sum(r["n_candidates"] for r in canon) == 322 and sum(len(r["released"]) for r in canon) == 293,
      "We call the 146 runs that used the five intents canonical runs", "contained 17 candidates, all of them released, and no unsupported proposal",
      "Canonical runs are the 146 runs")
nq = sum(r["n_clarification_questions"] for r in runs)
flag_runs = [r for r in runs if r["n_flagged"]]
check("67 questions in 50 runs; 12 flagged candidates from 9 runs, each with a question",
      nq == 67 and sum(1 for r in runs if r["n_clarification_questions"]) == 50 and sum(r["n_flagged"] for r in runs) == 12
      and len(flag_runs) == 9 and all(r["n_clarification_questions"] for r in flag_runs),
      "67 questions in all", "The twelve flagged candidates came from nine of these runs", "From nine runs")
ptf, cap = 2619.81, 3400.0            # EPİAŞ 2025 annual report, pp. 30-31
check("market example: 2,777 TRY/MWh; about 63,000 (6%) and 394,000 (38%)",
      round(ptf * 1.06) == 2777 and round(400 * (ptf * 1.06 - ptf), -3) == 63000 and round(400 * (cap * 1.06 - ptf), -3) == 394000
      and round(100 * (ptf * 1.06 - ptf) / ptf) == 6 and round(100 * (cap * 1.06 - ptf) / ptf) == 38,
      "2,777 TRY/MWh", "about TRY 63,000", "6% of its value", "about TRY 394,000, or 38%", "averaged 2,620 Turkish lira",
      "1,023 hours", "about 14 TWh", "TRY 42.3 billion")
check("'pre-registered' only in the sentence that explains the wording", both.count("pre-registered") == 1
      and "which is why we call the evaluation pre-specified and not pre-registered" in text)

P3 = json.load(open(os.path.join(ROOT, "results", "results_phase3.json")))
runs3 = json.load(open(os.path.join(ROOT, "results", "runs_phase3.json")))
T, A, G3 = P3["third_run"], P3["three_runs"], P3["gate"]
check("third run: 53 runs, 50/50 suite, 7/7 scenarios", P3["runs_scored"] == 53 and P3["invalid_outputs"] == 0
      and T["suite"]["released"]["k"] == 50 == T["suite"]["released"]["n"] and T["scenarios"]["released"]["k"] == 7 == T["scenarios"]["released"]["n"],
      "released all 50 suite variants and all seven scenario violations in the third run", "(53 runs)")
check("three runs: 49/50 every time [89.5-99.6], 50/50 at least once, 149/150 variant-runs, exception iv01 in run 2",
      A["suite"]["all_three_runs"]["k"] == 49 and ci(A["suite"]["all_three_runs"]) == "89.5–99.6%" and A["suite"]["at_least_one_of_three"]["k"] == 50
      and A["suite"]["item_runs"]["k"] == 149 and A["suite"]["item_runs"]["n"] == 150
      and A["suite"]["items_not_released_in_every_run"] == {"iv01": {"1": "released", "2": "suppressed:clarification", "3": "released"}}
      and A["scenarios"]["all_three_runs"]["k"] == 7,
      "49 of the 50 variants were released every time (98.0%; 95% interval 89.5–99.6%)", "Of the 150 variant-runs, 149 ended in a release")
fp3 = [x for r in runs3 for x in r["false_proposal_examples"]]
web = [x for x in fp3 if x["intent"] == "I4" and "443" in x["claim"]]
byp = [x for x in fp3 if x["intent"] == "I2" and "route" in x["claim"].lower()]
rest = [x for x in fp3 if x not in web and x not in byp]
check("third run: 11/78 unsupported = 14.1% [8.1-23.5], all stopped; 6 web management, 3 bypass, 2 restated (I1, I2)",
      G3["false_proposals"]["k"] == 11 and G3["actionable_proposed"] == 78 and ci(G3["false_proposals"]) == "8.1–23.5%"
      and p1(G3["false_proposals"]["p"]) == "14.1%" and G3["false_proposal_gate_outcome"] == {"not_supported": 11}
      and G3["false_alarms_released"] == 0 and len(web) == 6 and len(byp) == 3 and sorted(x["intent"] for x in rest) == ["I1", "I2"],
      "Of 78 actionable proposals, 11 (14.1%; 95% interval 8.1–23.5%) matched no ground truth", "Six repeated the claim", "three the bypass",
      "The other two restated a real management-plane violation under a second intent, I1 or I2")
for x in rest:      # the restated violation was itself released under I4 in the same run
    r = [r for r in runs3 if x in r["false_proposal_examples"]][0]
    check(f"restated proposal in run {r['run']}: violation released under I4", any(y["intent"] == "I4" for y in r["released"])
          and all(g["outcome"] == "released" for g in r["gt"]))
check("third run: 15/53 runs with a question = 28.3%", G3["runs_with_clarification"]["k"] == 15 and p1(G3["runs_with_clarification"]["p"]) == "28.3%",
      "Fifteen of the 53 runs (28.3%)")
CT3 = json.load(open(os.path.join(ROOT, "results", "clarification_topics_phase3.json")))
check("third run: same three leading clarification topics", set(CT3["runs_per_topic"]) == set(list(CT["runs_per_topic"])[:3]),
      "on the same three leading topics as before")

REC = json.load(open(os.path.join(ROOT, "results", "run_records.json")))["runs"]
phase = {}
for ph in (1, 2, 3):
    for rid in open(os.path.join(ROOT, "run", f"phase{ph}_ids.txt")).read().split():
        phase[rid] = ph
ok_l = {rid: [L for L in v if L["tool_calls"]] for rid, v in REC.items()}
check("run records: 211 runs, each with exactly one completed launch served by claude-haiku-5-5",
      len(REC) == 211 and all(len(v) == 1 and v[0]["model"] == ["claude-haiku-5-5"] for v in ok_l.values()),
      "every run was served by the model identifier given above")
def stray(L):
    return [t["name"] for t in L["tool_calls"] if t["name"] not in ("Read", "Write", "SubagentHandback")]
s12 = [rid for rid, v in ok_l.items() if phase[rid] in (1, 2) and stray(v[0])]
s3 = [rid for rid, v in ok_l.items() if phase[rid] == 3 and stray(v[0])]
sched = [rid for rid in s12 if any("send_later" in n for n in stray(ok_l[rid][0]))]
check("9/158 instances made other calls (7 scheduling); 2/53 in the third run; 13 rejected launches",
      len(s12) == 9 and len(sched) == 7 and len(s3) == 2 and sum(len(v) for v in REC.values()) - 211 == 13
      and all(phase[rid] == 3 for rid, v in REC.items() if len(v) > 1),
      "Nine of the 158 made other calls, seven of them to a scheduling tool", "two of the 53 instances of the third run",
      "Thirteen launches were rejected", "two instances made one stray tool call each")
check("every instance read only its own prompt and wrote only its own output",
      all(t["target"] == (f"/home/claude/exp/run/prompts/{rid}.txt" if t["name"] == "Read" else f"/home/claude/exp/run/outputs/{rid}.json")
          for rid, v in ok_l.items() for t in v[0]["tool_calls"] if t["name"] in ("Read", "Write")),
      "every instance read only its own prompt file and wrote only its own output file")
check("no placeholders", "{{" not in text and "AUTHOR" not in text)
print("FAILS:", fails)
