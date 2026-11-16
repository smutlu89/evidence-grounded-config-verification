# Results

Ground truth sha256 2cf6ebcd5321b5e9d66ae9e657450e8a1f911e0ef98f2938a6cd0b04be54b243; runs scored 158 {1: 105, 2: 53}; invalid outputs 0.

## Recall (released by the gate under the correct intent)

| Set | Items | Strict (all runs) | At least one run | Item-runs |
|---|---|---|---|---|
| Mutation suite (50 variants) | 50 | 49/50 (98.0%; 95% CI 89.5%–99.6%) | 50/50 (100.0%; 95% CI 92.9%–100.0%) | 99/100 (99.0%; 95% CI 94.6%–99.8%) |
| Scenarios S1-S3 (7 scored violations) | 7 | 7/7 (100.0%; 95% CI 64.6%–100.0%) | 7/7 (100.0%; 95% CI 64.6%–100.0%) | 14/14 (100.0%; 95% CI 78.5%–100.0%) |
| Latent set (10) | 10 | 10/10 (100.0%; 95% CI 72.2%–100.0%) | 10/10 (100.0%; 95% CI 72.2%–100.0%) | 10/10 (100.0%; 95% CI 72.2%–100.0%) |
| Suite, security variants (i–iii) | 39 | 39/39 (100.0%; 95% CI 91.0%–100.0%) | 39/39 (100.0%; 95% CI 91.0%–100.0%) | |
| Suite family i | 15 | 15/15 (100.0%; 95% CI 79.6%–100.0%) | 15/15 (100.0%; 95% CI 79.6%–100.0%) | 30/30 (100.0%; 95% CI 88.6%–100.0%) |
| Suite family ii | 12 | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 24/24 (100.0%; 95% CI 86.2%–100.0%) |
| Suite family iii | 12 | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 24/24 (100.0%; 95% CI 86.2%–100.0%) |
| Suite family iv | 11 | 10/11 (90.9%; 95% CI 62.3%–98.4%) | 11/11 (100.0%; 95% CI 74.1%–100.0%) | 21/22 (95.5%; 95% CI 78.2%–99.2%) |

Outcomes over item-runs:

* Mutation suite (50 variants): {'released': 99, 'suppressed:clarification': 1}; per run {1: 50/50 (100.0%; 95% CI 92.9%–100.0%), 2: 49/50 (98.0%; 95% CI 89.5%–99.6%)}
* Scenarios S1-S3 (7 scored violations): {'released': 14}; per run {1: 7/7 (100.0%; 95% CI 64.6%–100.0%), 2: 7/7 (100.0%; 95% CI 64.6%–100.0%)}
* Latent set (10): {'released': 10}; per run {1: 10/10 (100.0%; 95% CI 72.2%–100.0%)}
* family i: {'released': 30}
* family ii: {'released': 24}
* family iii: {'released': 24}
* family iv: {'released': 21, 'suppressed:clarification': 1}

## Compliant set

* True negatives 30/30; specificity 30/30 (100.0%; 95% CI 88.6%–100.0%)
* Upper bound on false-alarm rate (zero observed): {'rule_of_three': 0.1, 'exact': 0.09503385285530419}
* Ungated (exploratory): configurations with at least one false actionable proposal 5/30 (16.7%; 95% CI 7.3%–33.6%); by category {compliant_c1: 1/6 (16.7%; 95% CI 3.0%–56.4%), compliant_c2: 2/6 (33.3%; 95% CI 9.7%–70.0%), compliant_c3: 0/6 (0.0%; 95% CI 0.0%–39.0%), compliant_c4: 1/6 (16.7%; 95% CI 3.0%–56.4%), compliant_c5: 1/6 (16.7%; 95% CI 3.0%–56.4%)}
* I5 items released on compliant configurations 26 (informational on C4: 8)
* Configurations with a clarification 13

## Precision and F1

* Configuration level (gated): {'TP': 49, 'FP_configs': 0, 'precision': 1.0, 'recall': 0.98, 'F1': 0.98989898989899}
* Configuration level, ungated (exploratory): {'TP': 49, 'FP_configs': 13, 'precision': 0.7903225806451613, 'recall': 0.98, 'F1': 0.8749999999999999}
* Finding-level precision (gated): 145/145 (100.0%; 95% CI 97.4%–100.0%)
* Finding-level precision, ungated (exploratory): 145/162 (89.5%; 95% CI 83.8%–93.3%)

## Gate

* Candidates 339, released 310, suppressed 29: {'clarification': 12, 'not_supported': 17}
* By intent: {'I1': {'released': 36}, 'I2': {'clarification': 3, 'released': 52, 'not_supported': 4}, 'I3': {'released': 34, 'clarification': 5}, 'I4': {'released': 35, 'not_supported': 13, 'clarification': 3}, 'I5': {'released': 153, 'clarification': 1}}
* Canonical runs: actionable proposals 162, matching no ground truth 17/162 (10.5%; 95% CI 6.7%–16.2%); their gate outcome {'not_supported': 17}
* Ground-truth item-runs proposed but suppressed: {'suppressed:clarification': 1}
* Runs with a clarification: 50/158 (31.6%; 95% CI 24.9%–39.3%)

## Comparators

* Rule-only checker: {'security_detected': 39, 'security_total': 39, 'i5_detected': 11, 'i5_total': 11, 'latent_detected': 10, 'latent_total': 10, 'scenario_detected': 7, 'scenario_total': 7, 'compliant_false_alarm_configs': 0}
* Baseline comparison: {'raw_flagged': {'scenario': 3, 'suite': 50, 'compliant': 30, 'latent': 10}, 'norm_flagged': {'scenario': 3, 'suite': 50, 'compliant': 24, 'latent': 0}, 'surfaced': {'scenario_gt': 7, 'suite_gt': 48, 'family_i': 13, 'family_ii': 12, 'family_iii': 12, 'family_iv': 11, 'latent_gt': 0}, 'total': {'scenario': 3, 'scenario_gt': 7, 'suite': 50, 'suite_gt': 50, 'family_i': 15, 'family_ii': 12, 'family_iii': 12, 'family_iv': 11, 'compliant': 30, 'latent': 10, 'latent_gt': 10}, 'not_surfaced': {'i03': 1, 'i04': 1}}

## Phrasing sub-study

Summary {'detected': 11, 'missed': 1}

| Family | Question | Outcome | Released intents |
|---|---|---|---|
| i (i07) | Can anyone on the office network get into the control system? | missed | - |
| i (i05) | Is the plant firewall letting anything unusual through? | detected | I1, I2, I5 |
| i (i11) | Make sure vendors cannot get in any more. | detected | I1, I2 |
| ii (ii01) | Anything wrong with the VLANs? | detected | I3 |
| ii (ii03) | Are the switch ports in the control room set up correctly? | detected | I3 |
| ii (ii01) | Could anything bridge the office and plant networks at layer 2? | detected | I3 |
| iii (iii02) | Can somebody log in to the network devices from the office? | detected | I4, I5 |
| iii (iii04) | Check that remote administration is locked down. | detected | I4 |
| iii (iii01) | Is SNMP or telnet open anywhere it shouldn't be? | detected | I4 |
| iv (iv09) | Anything different from last month? | detected | I5 |
| iv (iv05) | Has anyone touched the configs recently? | detected | I5 |
| iv (iv01) | What changed since the approved baseline? | detected | I5 |

## Per template (canonical runs)

* latent:i01: {'released': 1}
* latent:i10: {'released': 1}
* latent:i13: {'released': 1}
* latent:ii01: {'released': 1}
* latent:ii05: {'released': 1}
* latent:ii09: {'released': 1}
* latent:iii01: {'released': 1}
* latent:iii04: {'released': 1}
* latent:iii07: {'released': 1}
* latent:iii10: {'released': 1}
* scenario:s1: {'released': 2}
* scenario:s2a: {'released': 2}
* scenario:s2b: {'released': 2}
* scenario:s3a: {'released': 2}
* scenario:s3b: {'released': 2}
* scenario:s3c: {'released': 2}
* scenario:s3d: {'released': 2}
* suite:i01: {'released': 2}
* suite:i02: {'released': 2}
* suite:i03: {'released': 2}
* suite:i04: {'released': 2}
* suite:i05: {'released': 2}
* suite:i06: {'released': 2}
* suite:i07: {'released': 2}
* suite:i08: {'released': 2}
* suite:i09: {'released': 2}
* suite:i10: {'released': 2}
* suite:i11: {'released': 2}
* suite:i12: {'released': 2}
* suite:i13: {'released': 2}
* suite:i14: {'released': 2}
* suite:i15: {'released': 2}
* suite:ii01: {'released': 6}
* suite:ii02: {'released': 2}
* suite:ii03: {'released': 4}
* suite:ii04: {'released': 2}
* suite:ii05: {'released': 2}
* suite:ii06: {'released': 2}
* suite:ii07: {'released': 2}
* suite:ii08: {'released': 2}
* suite:ii09: {'released': 2}
* suite:iii01: {'released': 4}
* suite:iii02: {'released': 2}
* suite:iii03: {'released': 2}
* suite:iii04: {'released': 4}
* suite:iii05: {'released': 2}
* suite:iii06: {'released': 2}
* suite:iii07: {'released': 2}
* suite:iii08: {'released': 2}
* suite:iii09: {'released': 2}
* suite:iii10: {'released': 2}
* suite:iv01: {'released': 1, 'suppressed:clarification': 1}
* suite:iv02: {'released': 2}
* suite:iv03: {'released': 2}
* suite:iv04: {'released': 2}
* suite:iv05: {'released': 2}
* suite:iv06: {'released': 2}
* suite:iv07: {'released': 2}
* suite:iv08: {'released': 2}
* suite:iv09: {'released': 2}
* suite:iv10: {'released': 2}
* suite:iv11: {'released': 2}
