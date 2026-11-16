#!/usr/bin/env python3
"""Audit of the Layer 2 agent transcripts.

For every subagent transcript that was started with the Layer 2 wrapper prompt, extract
run id, serving model, first/last event time, every tool call with its target, and
whether the launch failed before producing output.  Writes a JSON file; prints a summary.

usage: audit_runs.py <subagents_dir> <out.json> [<ids_file> ...]
"""
import glob
import json
import os
import re
import sys

sub_dir, out_path = sys.argv[1], sys.argv[2]
id_files = sys.argv[3:]
wanted = None
if id_files:
    wanted = set()
    for p in id_files:
        wanted |= {x.strip() for x in open(p) if x.strip()}

PROMPT_RE = re.compile(r"/home/claude/exp/run/prompts/([0-9a-f]{6})\.txt")
records = {}       # run id -> list of launches
for path in sorted(glob.glob(os.path.join(sub_dir, "agent-*.jsonl"))):
    agent_id = os.path.basename(path)[len("agent-"):-len(".jsonl")]
    rid = None
    wrapper = ""
    models, tools, times, errors = [], [], [], []
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            ts = d.get("timestamp")
            if ts:
                times.append(ts)
            m = d.get("message")
            if not isinstance(m, dict):
                continue
            c = m.get("content")
            if rid is None and m.get("role") == "user":
                text = c if isinstance(c, str) else " ".join(
                    b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
                mm = PROMPT_RE.search(text or "")
                if mm and "one component in a research pipeline" in text:
                    rid = mm.group(1)
                    wrapper = text.strip().replace(rid, "<id>")
            if m.get("role") == "assistant":
                mod = m.get("model")
                if mod and mod not in models:
                    models.append(mod)
                if d.get("isApiErrorMessage") or mod == "<synthetic>":
                    txt = " ".join(b.get("text", "") for b in (c or []) if isinstance(b, dict) and b.get("type") == "text")
                    # the runtime's message names the account's limit window; keep only the kind of error
                    errors.append("usage-limit error (HTTP 429): launch rejected before any model output"
                                  if "limit" in txt.lower() else txt[:160])
                if isinstance(c, list):
                    for b in c:
                        if isinstance(b, dict) and b.get("type") == "tool_use":
                            inp = b.get("input") or {}
                            target = inp.get("file_path") or inp.get("command") or inp.get("query") or ""
                            tools.append({"name": b.get("name"), "target": str(target)[:200]})
    if rid is None:
        continue
    if wanted is not None and rid not in wanted:
        continue
    records.setdefault(rid, []).append({
        "agent_id": agent_id,
        "wrapper_sha256_8": __import__("hashlib").sha256(wrapper.encode()).hexdigest()[:8],
        "wrapper_text": wrapper,
        "model": [x for x in models if x != "<synthetic>"],
        "first_event_utc": min(times) if times else None,
        "last_event_utc": max(times) if times else None,
        "tool_calls": tools,
        "api_errors": errors,
    })

for rid in records:
    records[rid].sort(key=lambda r: r["first_event_utc"] or "")

wrappers = {}
for v in records.values():
    for L in v:
        wrappers.setdefault(L["wrapper_sha256_8"], L.pop("wrapper_text"))
        L.pop("wrapper_text", None)
json.dump({"wrapper_variants": wrappers, "runs": records}, open(out_path, "w"), indent=1, sort_keys=True)

# ---- summary
n_launch = sum(len(v) for v in records.values())
print("runs", len(records), "launches", n_launch)
import collections
print("wrapper variants (launch counts):", dict(collections.Counter(L["wrapper_sha256_8"] for v in records.values() for L in v)))
allmodels = {}
stray = []
failed = []
badtarget = []
for rid, launches in sorted(records.items()):
    for L in launches:
        for mo in L["model"]:
            allmodels[mo] = allmodels.get(mo, 0) + 1
        names = [t["name"] for t in L["tool_calls"]]
        if not names and (L["api_errors"] or not L["model"]):
            failed.append((rid, L["agent_id"], (L["api_errors"] or ["no assistant turn"])[0][:70]))
            continue
        extra = [t for t in L["tool_calls"] if t["name"] not in ("Read", "Write", "SubagentHandback")]
        if extra:
            stray.append((rid, L["agent_id"], [(t["name"], t["target"][:60]) for t in extra]))
        for t in L["tool_calls"]:
            if t["name"] == "Read" and t["target"] != f"/home/claude/exp/run/prompts/{rid}.txt":
                badtarget.append((rid, L["agent_id"], "Read", t["target"]))
            if t["name"] == "Write" and t["target"] != f"/home/claude/exp/run/outputs/{rid}.json":
                badtarget.append((rid, L["agent_id"], "Write", t["target"]))
print("models", allmodels)
print("failed launches", len(failed))
for f in failed:
    print("  ", f)
print("launches with tool calls other than Read/Write/SubagentHandback:", len(stray))
for s in stray:
    print("  ", s)
print("Read/Write on a file other than the run's own prompt/output:", len(badtarget))
for b in badtarget:
    print("  ", b)
ts = [L["first_event_utc"] for v in records.values() for L in v if L["first_event_utc"]]
te = [L["last_event_utc"] for v in records.values() for L in v if L["last_event_utc"]]
print("first event", min(ts) if ts else None, "last event", max(te) if te else None)
