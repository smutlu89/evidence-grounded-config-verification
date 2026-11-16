# Evaluation protocol (fixed before any Layer 2 run)

Fixed on 2026-11-03 (UTC) before the first evaluation run. SHA-256 hashes of this file, the code and the prompts are recorded in `run/HASHES.txt`. Any later change is logged in `DEVIATIONS.md`.

## 1. Questions

1. Recall on injected boundary violations (mutation suite and scenarios S1–S3).
2. Behaviour on compliant configurations (false alarms, specificity, precision, F1).
3. Detection of latent violations that a baseline comparison cannot see.
4. Effect of colloquial, under-specified operator questions (phrasing sub-study).
5. How often the deterministic gate suppresses model output, and why.

## 2. Topology, devices and site data

Synthetic three-zone energy network: OT control zone 10.10.10.0/24 (VLAN 10), DMZ 10.10.20.0/24 (VLAN 20), corporate IT 192.168.30.0/24 (VLAN 30), management VLAN 10.10.99.0/24 (VLAN 99), vendor VPN pool 172.16.50.0/24. Five devices: one Cisco ASA firewall (fw-01, ASA 9.8 syntax), one ISR edge router (rtr-01, IOS-XE 16.9 syntax) and three Catalyst 3750-X switches (sw-core-01, sw-ot-01, sw-it-01, IOS 15.2 syntax). Approved baseline: 911 configuration lines, 197 evidence records. Zone registry, approved services, port roles, approved trunks, management policy and outage register: `evalkit/site.py`.

## 3. Intents

I1 SCADA isolation, I2 DMZ mediation, I3 boundary enforcement, I4 management-plane restriction, I5 baseline consistency. Exact wording: `evalkit/prompt.py`.

## 4. Datasets (seed 20261103)

| Set | Size | Content |
|---|---|---|
| Scenarios S1–S3 | 3 snapshots, 7 scored violations | S1 one IT-to-OT rule; S2 OT port in corporate VLAN, permissive trunk, plus one authorized shutdown (informational, not scored); S3 two permissive ACL entries, remote logging to a corporate host, read-write SNMP community |
| Mutation suite | 50 variants | (i) ACL permutations 15; (ii) VLAN and trunk errors 12; (iii) management-service exceptions 12; (iv) baseline-only deltas 11. One injected change per variant. |
| Compliant set | 30 configurations | C1 timestamp-only changes; C2 approved flows added; C3 deny-only IT-to-OT entries; C4 authorized shutdowns; C5 post-rollback states (neutral reordering, residual remarks or descriptions). 6 per category. |
| Latent set | 10 | A violation present in the approved baseline itself; the snapshot differs only in volatile lines. |
| Phrasing sub-study | 12 | Three suite variants per family, each with one colloquial question (list in `build_runs.py`). |

Dataset QA (before any model run): the rule-only checker must reproduce the ground truth of every item exactly, report no I1–I4 finding on any compliant configuration and report no baseline delta for C1 and latent items.

## 5. Layer 2 (language model)

Claude Haiku 5.5, invoked as an independent sub-agent of the Claude agent runtime (model alias `haiku`) with default decoding settings, one fresh agent per run. No fine-tuning, no worked examples. The agent reads one prompt file and writes one JSON file; it is instructed to use no other tool. The prompt contains the zone registry, the intents, the evidence records and the baseline deltas, never the raw configuration. Runs (revised before the first evaluation run, see DEVIATIONS.md): every item once (phase 1, 105 runs); suite and scenarios a second time (phase 2, 53 runs); a third suite and scenario run only if resources allow (phase 3, reported separately). Missing or malformed JSON: one re-run with a fresh agent; if still invalid, the run counts as returning no candidates.

## 6. Layer 3 (gate)

`evalkit/gate.py`. A candidate is released only if it is well formed, its clarification flag is not set, every cited anchor exists, I1/I2 zone selectors are registry zone names, and at least one cited anchor is confirmed by the deterministic check for the claimed intent with the same zones. Rejected candidates are not returned to the model.

## 7. Blinding

The ground truth and the mapping from run identifiers to items are encrypted (AES-256, key held outside the run directory) until all runs are complete. Prompt files carry random identifiers.

## 8. Scoring

* A ground-truth item is detected in a run if a released finding has an intent in the item's intent set and cites, or is confirmed on, an accepted anchor. Security violations (families i–iii, S1–S3, latent) must be released under a security intent (I1–I4); baseline-only deltas (family iv) under I5.
* Suite recall (strict): a variant counts as detected only if it is detected in every executed run. Also reported: detected in at least one run; per-run recall. 95% Wilson score intervals.
* False alarm: a released actionable finding (I1–I4) that matches no ground-truth item of its snapshot.
* Compliant set: a configuration is a true negative only if its run releases no false alarm. Specificity = TN / 30. If no false alarm occurs, the one-sided 95% upper bound is reported (3/n rule and exact).
* Configuration-level precision (strict): TP = suite variants detected in every executed run; FP = configurations (suite or compliant) with a false alarm in any executed run. F1 = 2PR/(P+R).
* Finding-level precision: released actionable findings that match ground truth / all released actionable findings.
* Gate statistics: candidates proposed, released and suppressed by reason; share of proposed actionable candidates that the gate would have had to stop.
* Comparators: rule-only checker (same rules as the gate, no model); baseline comparison on raw text and on normalized lines.
* Latent set: detection per variant; the baseline comparison cannot detect any by construction.
* Phrasing sub-study: per question, one of detected, clarification requested, missed, or false release.
