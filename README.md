# Evidence-grounded configuration verification: evaluation package

Data, code and records behind Sections 11.6 and 11.7 of

> Mutlu, S., & Karaarslan, E. (forthcoming). Securing digitalized energy market boundaries: An evidence-grounded
> AI framework for configuration resilience. In B. Bagis (Ed.), *AI-Driven Decision-Making in Finance*
> (Chapter 11). CRC Press.

The package contains the synthetic configurations, the pipeline code, the protocol fixed before the runs, every
prompt and model output, the run records, the ground truth and the scoring. **All configurations are synthetic;
no production data are included.**

## What was evaluated

A three-layer verifier for firewall, router and switch configurations at the boundary between plant (OT) and
corporate (IT) networks:

1. **Layer 1** (deterministic, `evalkit/parser.py`, `evalkit/delta.py`): parses configuration snapshots into
   line-anchored evidence records and computes deltas against the approved baseline.
2. **Layer 2** (language model, prompt in `evalkit/prompt.py`): proposes candidate findings that cite evidence
   anchors, and may ask clarification questions.
3. **Layer 3** (deterministic, `evalkit/gate.py`, `evalkit/checks.py`): releases a candidate only if its own
   order-, binding- and approved-service-aware check confirms the claim on a cited anchor.

## What was run

* Topology: five devices (fw-01 ASA 9.8, rtr-01 ISR IOS-XE 16.9, sw-core-01 / sw-ot-01 / sw-it-01 Catalyst 3750-X
  IOS 15.2); approved baseline 911 lines, 197 evidence records. Zone registry and intents: `evalkit/site.py`.
* Items (seed 20261103): 3 scenarios (7 scored violations), 50 mutation-suite variants, 30 compliant
  configurations, 10 latent violations, plus 12 colloquial questions (phrasing sub-study). 93 items.
* Layer 2: Claude Haiku 5.5 (`claude-haiku-5-5`), one fresh agent instance of the Claude agent runtime per run,
  runtime default decoding (not exposed by the runtime), no fine-tuning, no worked examples.
* **Primary analysis: 158 runs on 3 November 2026 (UTC).** Phase 1 = every item once and each question once
  (105 runs); phase 2 = suite and scenarios again (53 runs).
* **Phase 3: 53 runs on 15 November 2026 (UTC)**, a third run of the suite and the scenarios. It was made after
  the primary results were known and is therefore reported separately; it changes no primary result
  (`DEVIATIONS.md`, item 8).

## Results in brief

| | Primary analysis (phases 1–2) | Phase 3 (reported separately) |
|---|---|---|
| Suite variants released under the correct intent | 49/50 in both runs (95% Wilson interval 89.5–99.6%); 50/50 in at least one run | 50/50 in the third run; 49/50 in all three runs |
| Scenario violations released | 7/7 in both runs | 7/7 |
| Latent violations released | 10/10 | not run |
| False alarms released on 30 compliant configurations | 0 | not run |
| Actionable proposals that matched no ground truth (all stopped by the gate) | 17/162 = 10.5% | 11/78 = 14.1% |
| Runs with a clarification question | 50/158 | 15/53 |

On this dataset the gate releases only what the deterministic checks confirm, and dataset QA required those
checks to reproduce the ground truth. Zero released false alarms and a perfect rule-only checker are therefore
properties of the design, not empirical findings; see the chapter, Section 11.6.4. Full results:
`results/results.md` and `results/results_phase3.md`.

## Pre-specification

`PROTOCOL.md`, the code in `evalkit/`, `build_runs.py`, the run-id lists and all 271 prompts were fixed before the
first run, and their SHA-256 hashes were recorded in `run/HASHES.txt` (2026-11-03T20:37:46Z). The ground truth and
the run-to-item mapping were AES-256 encrypted until all runs of the primary analysis were complete. The record
was kept locally and is published here; it was **not deposited in a public registry beforehand**. The evaluation
is therefore pre-specified, not pre-registered. Every deviation from the protocol is logged in `DEVIATIONS.md`,
including a correction of the scoring script (item 7) and the later third run (item 8).

## Files

| Path | Content |
|---|---|
| `PROTOCOL.md` | Protocol fixed before the first run (hash in `run/HASHES.txt`) |
| `DEVIATIONS.md` | Every deviation from the protocol, in order |
| `evalkit/` | Baseline generator, parser (Layer 1), deltas, checks and gate (Layer 3), prompt template (Layer 2), dataset generator, dataset QA |
| `build_runs.py` | Builds prompts, dataset folders and the sealed ground truth |
| `score.py` | Decrypts the ground truth, gates every output, computes all metrics and comparators; primary analysis and phase 3 are written to separate files |
| `analysis_clarifications.py` | Exploratory topic count of clarification questions |
| `audit_runs.py` | Extracts the run records from the agent transcripts (the transcripts themselves are not distributed, see below) |
| `check_claims.py` | Cross-checks the numbers in the chapter text and tables against `results/`; needs the chapter source, which is not part of this repository |
| `run/prompts/` | All 271 prompts that were built (211 executed; see `run/phase1_ids.txt`, `run/phase2_ids.txt`, `run/phase3_ids.txt`) |
| `run/outputs/` | The 211 model outputs, exactly as written by the model (`run/OUTPUT_HASHES.txt`) |
| `run/dataset/<item>/` | Baseline and snapshot configurations of each item (neutral item identifiers) |
| `run/ground_truth.json` | Decrypted ground truth and run-to-item mapping (sha256 of the decrypted blob: 2cf6ebcd5321b5e9d66ae9e657450e8a1f911e0ef98f2938a6cd0b04be54b243) |
| `run/ground_truth.json.enc`, `run/ground_truth.key.txt` | The sealed file used during the runs and its key, so that the decryption can be repeated |
| `run/HASHES.txt` | SHA-256 of protocol, code, id lists and prompts, recorded before the first run |
| `results/results.md`, `results/results.json` | All metrics of the primary analysis (corrected scoring) |
| `results/runs.json` | Per-run detail of the primary analysis: released and suppressed candidates, outcome per ground-truth item |
| `results/results_phase3.md`, `results/results_phase3.json`, `results/runs_phase3.json` | The same for phase 3 |
| `results/SHA256SUMS_main.txt` | Hashes of the primary result files as they stood before phase 3 was scored; they are unchanged |
| `results/results_first_pass.json` | Metrics from the first scoring pass, before the correction in `DEVIATIONS.md` item 7 |
| `results/clarification_topics.json`, `results/clarification_topics_phase3.json` | Clarification questions and flagged claims with their topic |
| `results/run_records.json`, `results/run_records_summary.txt` | Per launch: serving model, first and last event (UTC), every tool call and its target, wording of the wrapper instruction |
| `results/agent_final_reports.json`, `results/agent_final_reports_phase3.json` | The final message of each model instance (not scored; kept for transparency) |
| `pilot/` | Two pilot prompts from a held-out seed (7) and their outputs, run before the evaluation |

## Reproducing the scoring

```
python3 -m evalkit.validate                      # dataset QA: "items 93 problems 0"
head -16 run/HASHES.txt | sha256sum -c -         # all OK except DEVIATIONS.md, which is a running log
cat run/prompts/*.txt | sha256sum                # compare with line 17 of run/HASHES.txt
(cd run && sha256sum -c OUTPUT_HASHES.txt)       # the 211 model outputs
python3 score.py                                 # writes results/*; key is read from run/ground_truth.key.txt
sha256sum -c results/SHA256SUMS_main.txt
python3 analysis_clarifications.py
python3 analysis_clarifications.py runs_phase3.json clarification_topics_phase3.json
```

Python 3.10+ with the standard library only; `openssl` for the decryption. Scoring is deterministic. Running
Layer 2 again requires access to the model and will not reproduce the outputs token by token.

## What is not included

* The agent transcripts. They contain the runtime's own system prompt and tool definitions. What the chapter
  relies on (serving model, tool calls and their targets, timing) is extracted in `results/run_records.json`.
* The chapter text.

## Limitations of the run conditions

The model instances ran in a general-purpose agent runtime with other tools available and were restricted by
instruction, not by a sandbox. Eleven of the 211 instances made a call outside the two permitted tools,
the runtime's own hand-back call aside (`DEVIATIONS.md`, items 2 to 5 and 8); the run records show that every instance read only its own prompt and
wrote only its own output. Decoding parameters could not be set or read.

## Use of generative AI

Under the authors' direction, Claude (Anthropic) assisted in designing, coding and running this evaluation. The
authors reviewed and verified the code, data and results and take full responsibility for them.

## License and citation

Code: MIT License. Data, prompts, outputs and documentation: Creative Commons Attribution 4.0 International
(CC BY 4.0). See `LICENSE`. Please cite the chapter above; `CITATION.cff` has the details.

Contact: Sedat Mutlu and Enis Karaarslan, Muğla Sıtkı Koçman University, Faculty of Engineering, Muğla, Türkiye.
