# Results of phase 3 (third suite and scenario run; reported separately, DEVIATIONS.md item 8)

Ground truth sha256 2cf6ebcd5321b5e9d66ae9e657450e8a1f911e0ef98f2938a6cd0b04be54b243; runs scored 53 {'suite': 50, 'scenario': 3}; invalid outputs 0.

## Third run alone (released by the gate under the correct intent)

* Mutation suite: 50/50 (100.0%; 95% CI 92.9%–100.0%); outcomes {'released': 50}
* Suite, security variants (i–iii): 39/39 (100.0%; 95% CI 91.0%–100.0%)
* Suite family i: 15/15 (100.0%; 95% CI 79.6%–100.0%); outcomes {'released': 15}
* Suite family ii: 12/12 (100.0%; 95% CI 75.8%–100.0%); outcomes {'released': 12}
* Suite family iii: 12/12 (100.0%; 95% CI 75.8%–100.0%); outcomes {'released': 12}
* Suite family iv: 11/11 (100.0%; 95% CI 74.1%–100.0%); outcomes {'released': 11}
* Scenario violations: 7/7 (100.0%; 95% CI 64.6%–100.0%); outcomes {'released': 7}

## Three runs together (phases 1, 2 and 3)

| Set | Items | Released in all three runs | Released in at least one | Item-runs |
|---|---|---|---|---|
| Mutation suite | 50 | 49/50 (98.0%; 95% CI 89.5%–99.6%) | 50/50 (100.0%; 95% CI 92.9%–100.0%) | 149/150 (99.3%; 95% CI 96.3%–99.9%) |
| Suite, security variants (i–iii) | 39 | 39/39 (100.0%; 95% CI 91.0%–100.0%) | 39/39 (100.0%; 95% CI 91.0%–100.0%) | 117/117 (100.0%; 95% CI 96.8%–100.0%) |
| Suite family i | 15 | 15/15 (100.0%; 95% CI 79.6%–100.0%) | 15/15 (100.0%; 95% CI 79.6%–100.0%) | 45/45 (100.0%; 95% CI 92.1%–100.0%) |
| Suite family ii | 12 | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 36/36 (100.0%; 95% CI 90.4%–100.0%) |
| Suite family iii | 12 | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 12/12 (100.0%; 95% CI 75.8%–100.0%) | 36/36 (100.0%; 95% CI 90.4%–100.0%) |
| Suite family iv | 11 | 10/11 (90.9%; 95% CI 62.3%–98.4%) | 11/11 (100.0%; 95% CI 74.1%–100.0%) | 32/33 (97.0%; 95% CI 84.7%–99.5%) |
| Scenario violations | 7 | 7/7 (100.0%; 95% CI 64.6%–100.0%) | 7/7 (100.0%; 95% CI 64.6%–100.0%) | 21/21 (100.0%; 95% CI 84.5%–100.0%) |

Items not released in every run (template: outcome per run): {'iv01': {'1': 'released', '2': 'suppressed:clarification', '3': 'released'}} {}

## Gate, phase 3

* Candidates 145, released 129 {'I1': 15, 'I2': 23, 'I3': 14, 'I4': 15, 'I5': 62}, suppressed 16: {'not_supported': 11, 'clarification': 5}
* Actionable proposals 78, matching no ground truth 11/78 (14.1%; 95% CI 8.1%–23.5%) {'I4': 6, 'I2': 4, 'I1': 1}; their gate outcome {'not_supported': 11}
* Released actionable findings 67, of which false 0
* Configurations with at least one false actionable proposal 9/53 (17.0%; 95% CI 9.2%–29.2%)
* Ground-truth item-runs proposed but suppressed: {}
* Runs with a clarification: 15/53 (28.3%; 95% CI 18.0%–41.6%)

