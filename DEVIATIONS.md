# Deviations from the protocol

1. 2026-11-03, before the first evaluation run (no evaluation output existed). A pilot on two prompts built from a
   held-out seed (7) confirmed that the agents read the prompt, write valid JSON and that the gate processes the output.
   Each agent run consumed about 85,000 tokens. The run plan was therefore reduced from 271 to 158 runs
   (plus 53 optional): every item is run once (phase 1, 105 runs); the suite and the scenarios receive a second run
   (phase 2, 53 runs); a third suite and scenario run (phase 3, 53 runs) is executed only if resources allow and is
   reported separately. The compliant set is run once. Prompts, data, gate and scoring rules are unchanged.
   The strict detection criterion becomes "detected in every executed run".

2. 2026-11-03, phase 1, first batch. The agent of run 00e18e made unrequested tool calls unrelated to the task after
   writing its output (a tool search and a scheduling call that queued a "noop" message to the orchestrating session;
   its attempt to delete that message was refused by the runtime). Its output file was produced from the prompt and is
   kept. From the second batch on, the wrapper instruction given to each agent adds one sentence forbidding any tool
   other than Read and Write (no scheduling, searching or messaging). The Layer 2 prompt files are unchanged.

3. 2026-11-03, phase 1, sixth batch. The agents of runs a68d91 and 8ebf3b again made one unrequested scheduling call
   each after writing their output (a one-shot message to the orchestrating session; their attempts to delete it were
   refused by the runtime, and the messages fired once at 20:51 and 20:52 UTC). Both output files were produced from
   the prompt and are kept. From the seventh batch on, the wrapper names the forbidden tools explicitly
   (scheduling, trigger, search, shell and messaging tools) and states that the task ends when the file is written.
   The Layer 2 prompt files are unchanged.

4. 2026-11-03, phase 2, first batch. The agent of run 11b512 made one read-only call to a scheduling list tool
   (it returned an empty list and changed nothing) before writing its output. The output file is kept.

5. 2026-11-03, after phase 2 and before the ground truth was decrypted. An audit of all agent transcripts found
   that 9 of the 158 evaluation runs made at least one call to a tool other than Read and Write:
   seven runs called the scheduling tool (00e18e, 258279, a68d91, 8ebf3b, 44d350, 612e0d, bad104; four of these
   calls created a one-shot message to the orchestrating session, three failed input validation and created nothing),
   one run listed scheduled tasks (11b512, read-only) and one run made a tool search (77ac5d, read-only).
   No run read any file other than its prompt, and every output file was written by the run's own agent.
   All 158 outputs are kept and scored.

6. 2026-11-03, before the ground truth was decrypted. Phase 3 (a third suite and scenario run) is not executed:
   the remaining time and token budget is used for scoring and reporting. The strict criterion is therefore
   "detected in both executed runs" for the suite and the scenarios, and "detected in the single run" for the
   latent set; the compliant set and the phrasing sub-study have one run each, as planned.

7. 2026-11-03, scoring (after decryption). The first scoring pass matched a released finding to ground truth only
   through the anchors it cited and the anchors of the checker findings that confirmed it. The dataset QA
   (validate.py, fixed before the runs) also accepts the related anchors of the confirming checker finding (for a
   baseline delta, the record of the section that contains it). Without them, variant iv08 (a child line removed
   from an interface) could not be matched by any I5 finding citing the delta anchor, which is what the prompt
   instructs. score.py was corrected to use the QA matching rule. First pass: suite strict recall 48/50, family iv
   9/11; corrected: 49/50 and 10/11. No other number changed. Both result files are kept
   (results/results_first_pass.json, results/results.json).

8. 2026-11-15, twelve days after the main analysis (ground truth decrypted on 3 November; results known and written
   up). A review of the finished chapter by the co-author asked for a larger evaluation or, failing that, for the
   optional third suite and scenario run. Phase 3 (53 runs; prompts built and hashed on 3 November, see item 1) was
   therefore executed after all, which reverses item 6. Because the results of phases 1 and 2 were known when it
   was run, phase 3 is not part of the main analysis: the primary results remain those of the 158 runs of phases 1
   and 2, and phase 3 is reported separately as a consistency check (results/results_phase3.md,
   results_phase3.json, runs_phase3.json), as item 1 provides.
   Conditions: the same prompt files (hash of run/prompts unchanged), one fresh agent per run, the same model
   alias, which resolved to claude-haiku-5-5 in all 53 runs, and the wrapper instruction of the last 41 runs of
   phase 2. While the runs were executed, the decrypted ground truth, the copy of the key and the results folder
   were moved out of the package folder; the transcripts show that every agent read only its own prompt file and
   wrote only its own output file. First event 2026-11-15T17:50:15Z, last event 2026-11-15T22:42:29Z.
   Events: (a) thirteen launches (d3aa54, d47ff1, d5590c, d95225, e3d5bd, e4cfb5, e687f3, ec3b48, ed5724, f0aef2,
   f4f1af, f80464, f890c7) were rejected with a usage-limit error (HTTP 429) before any model output or tool call
   and were launched again, unchanged, after the limit was reset; there are therefore 66 launches for 53 runs, and
   no completed run was repeated or discarded. (b) Two runs made one stray tool call each after writing their
   output: 9921c4 a shell call to a linked device (command "true"; refused by the runtime, nothing was executed)
   and e3d5bd a read-only listing of scheduled tasks (empty). (c) Run 9849b1 ended without the final hand-back
   message; its output file had been written and is kept. All 53 outputs are valid JSON and are scored with the
   unchanged gate and matching rule.
   Scoring: score.py was changed only to separate the runs by phase. results/results.json, results/results.md,
   results/runs.json and results/clarification_topics.json are byte-identical to the files of the main analysis
   (results/SHA256SUMS_main.txt).
   Correction to the record: the transcript audit made for this item (results/run_records.json) shows that the
   wrapper instruction had four wordings on 3 November, not three. After item 4 the tool "list_triggers" was added
   to the tools named as forbidden, for the remaining 41 runs of phase 2; item 4 does not mention this. The four
   wordings and the launches that used each are listed in results/run_records.json.
