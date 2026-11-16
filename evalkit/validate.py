"""Dataset QA: the rule-only checker must reproduce exactly the injected ground truth."""
from . import gen, parser, delta, checks


def evidence(item):
    recs = parser.parse_all(item["snap"])
    dels = delta.deltas_all(item["base"], item["snap"])
    return recs, dels


def explain(item, findings):
    """Return (missed GT items, unexplained security findings)."""
    sec = [f for f in findings if f["intent"] != "I5"]
    i5 = [f for f in findings if f["intent"] == "I5"]
    missed, unexplained = [], []
    for g in item["gt"]:
        pool = i5 if g["intents"] == ["I5"] else sec
        hit = [f for f in pool if f["intent"] in g["intents"] and (f["anchor"] in g["accept"] or set(f.get("related", [])) & set(g["accept"]))]
        if not hit:
            missed.append(g)
    acc = {(i, a) for g in item["gt"] for i in g["intents"] for a in g["accept"]}
    for f in sec:
        if (f["intent"], f["anchor"]) not in acc:
            unexplained.append(f)
    return missed, unexplained


def run():
    base, items = gen.build()
    problems = 0
    for it in items:
        recs, dels = evidence(it)
        f = checks.check(recs, dels)
        missed, unexpl = explain(it, f)
        n_i5 = sum(1 for x in f if x["intent"] == "I5")
        bad = bool(missed or unexpl)
        if it["set"].startswith("compliant") and any(x["intent"] != "I5" for x in f):
            bad = True
        if it["set"] == "compliant_c1" and n_i5:
            bad = True
        if it["set"] == "latent" and n_i5:
            bad = True
        if bad:
            problems += 1
            print("PROBLEM", it["set"], it["idx"], [g["template"] for g in it["gt"]],
                  "missed", [g["desc"] for g in missed], "unexplained", [(x["intent"], x["anchor"], x["reason"]) for x in unexpl],
                  "i5", n_i5)
    print("items", len(items), "problems", problems)
    return base, items


if __name__ == "__main__":
    run()
