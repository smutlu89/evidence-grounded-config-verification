"""Build the evaluation runs: prompts (public), dataset (neutral ids) and the sealed ground truth."""
import hashlib
import json
import os
import random
import subprocess
import sys
from evalkit import gen, parser, delta, prompt

ROOT = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(ROOT, "run")
RUNS_PER_SET = {"scenario": 3, "suite": 3, "compliant": 3, "latent": 1}

QUESTIONS = {   # phrasing sub-study: colloquial operator questions, fixed before the runs
    "i":   ["Can anyone on the office network get into the control system?",
            "Is the plant firewall letting anything unusual through?",
            "Make sure vendors cannot get in any more."],
    "ii":  ["Are the switch ports in the control room set up correctly?",
            "Could anything bridge the office and plant networks at layer 2?",
            "Anything wrong with the VLANs?"],
    "iii": ["Can somebody log in to the network devices from the office?",
            "Check that remote administration is locked down.",
            "Is SNMP or telnet open anywhere it shouldn't be?"],
    "iv":  ["What changed since the approved baseline?",
            "Has anyone touched the configs recently?",
            "Anything different from last month?"],
}


def main(seed=20261103):
    base, items = gen.build(seed)
    rng = random.Random(seed + 1)
    os.makedirs(os.path.join(RUN, "prompts"), exist_ok=True)
    os.makedirs(os.path.join(RUN, "outputs"), exist_ok=True)
    os.makedirs(os.path.join(RUN, "dataset"), exist_ok=True)
    sealed = {"seed": seed, "items": {}, "runs": {}}
    used = set()

    def rid():
        while True:
            x = "%06x" % rng.randrange(16 ** 6)
            if x not in used:
                used.add(x); return x

    def write_item(it):
        sid = rid()
        d = os.path.join(RUN, "dataset", sid)
        os.makedirs(os.path.join(d, "baseline"), exist_ok=True); os.makedirs(os.path.join(d, "snapshot"), exist_ok=True)
        for dev in it["snap"]:
            open(os.path.join(d, "baseline", dev + ".cfg"), "w").write("\n".join(it["base"][dev]) + "\n")
            open(os.path.join(d, "snapshot", dev + ".cfg"), "w").write("\n".join(it["snap"][dev]) + "\n")
        recs = parser.parse_all(it["snap"]); dels = delta.deltas_all(it["base"], it["snap"])
        sealed["items"][sid] = {"set": it["set"], "idx": it["idx"], "gt": it["gt"]}
        return sid, recs, dels

    plan = []
    for it in items:
        sid, recs, dels = write_item(it)
        kind = it["set"].split("_")[0]
        p = prompt.build(recs, dels)
        for r in range(1, RUNS_PER_SET[kind] + 1):
            plan.append((sid, "canonical", None, r, p))
        it["sid"] = sid; it["recs"] = recs; it["dels"] = dels
    # phrasing sub-study: three suite variants per family, one question each
    suite = [it for it in items if it["set"] == "suite"]
    for fam, qs in QUESTIONS.items():
        pool = [it for it in suite if it["gt"][0]["family"] == fam]
        for q, it in zip(qs, rng.sample(pool, 3)):
            plan.append((it["sid"], "question", q, 1, prompt.build(it["recs"], it["dels"], question=q)))
    rng.shuffle(plan)
    for sid, mode, q, r, text in plan:
        run_id = rid()
        open(os.path.join(RUN, "prompts", run_id + ".txt"), "w").write(text)
        sealed["runs"][run_id] = {"item": sid, "mode": mode, "question": q, "run": r}
    open(os.path.join(RUN, "run_ids.txt"), "w").write("\n".join(sorted(sealed["runs"])) + "\n")
    # seal the ground truth and the run-to-item mapping
    key = open("/root/.exp_gt_key").read().strip()
    blob = json.dumps(sealed, indent=1).encode()
    enc = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-pass", "pass:" + key],
                         input=blob, capture_output=True, check=True).stdout
    open(os.path.join(RUN, "ground_truth.json.enc"), "wb").write(enc)
    print("items", len(items), "runs", len(plan), "gt sha256", hashlib.sha256(blob).hexdigest())


if __name__ == "__main__":
    main()
