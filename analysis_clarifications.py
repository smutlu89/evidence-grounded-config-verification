"""Exploratory (not specified in the protocol): topics of the model's clarification questions and flagged candidates.

Each question or flagged claim is assigned to the first matching topic by keyword; a run counts once per topic.
Writes results/clarification_topics.json (main analysis, phases 1 and 2). With two arguments
(runs_phase3.json clarification_topics_phase3.json) the same count is made for the separately reported phase 3.
"""
import json
import os
from collections import Counter

ROOT = os.path.dirname(os.path.abspath(__file__))
TOPICS = [
    ("trunks carrying VLAN 10 vs. 'only OT-facing ports active in VLAN 10'", lambda t: "vlan 10" in t and "trunk" in t),
    ("firewall HTTP server / tcp 443 to the firewall's outside address", lambda t: "http" in t or "asdm" in t or "443" in t),
    ("router default routes / management port", lambda t: "route" in t or "bypass" in t),
    ("ports in the outage register / shutdowns", lambda t: "outage" in t or "gi1/0/9" in t or "shutdown" in t),
    ("NTP server", lambda t: "ntp" in t),
    ("VLAN 99 management interfaces (SVIs)", lambda t: "vlan99" in t or "vlan 99" in t or "svi" in t),
]


def main(runs_file="runs.json", out_file="clarification_topics.json"):
    runs = json.load(open(os.path.join(ROOT, "results", runs_file)))
    per_topic, texts = Counter(), []
    for r in runs:
        d = json.load(open(os.path.join(ROOT, "run", "outputs", r["run"] + ".json")))
        items = [q.get("question", "") for q in d.get("clarifications", []) if isinstance(q, dict)]
        items += [c.get("claim", "") for c in d.get("candidates", []) if isinstance(c, dict) and c.get("clarification_flag") is True]
        seen = set()
        for t in items:
            topic = next((name for name, f in TOPICS if f(t.lower())), "other")
            seen.add(topic)
            texts.append({"run": r["run"], "topic": topic, "text": t})
        for s in seen:
            per_topic[s] += 1
    out = {"runs_with_clarification": sum(1 for r in runs if r["n_flagged"] or r["n_clarification_questions"]),
           "texts": len(texts), "runs_per_topic": dict(per_topic.most_common()), "items": texts}
    json.dump(out, open(os.path.join(ROOT, "results", out_file), "w"), indent=1)
    return out


if __name__ == "__main__":
    import sys
    o = main(*sys.argv[1:3])      # optional: runs_phase3.json clarification_topics_phase3.json
    print(o["runs_with_clarification"], o["texts"], o["runs_per_topic"])
    for x in o["items"]:
        print(x["topic"][:12], "|", x["text"][:115])
