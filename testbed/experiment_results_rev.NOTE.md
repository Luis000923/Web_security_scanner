# Note on experiment_results_rev.csv

`AI_FN_Introduced` for the four `ai-triage` rows was corrected by hand on
2026-11-19 (0,0,0,0 -> 5,6,5,1). `run_experiments.py` graded suppressions
against the pre-triage telemetry set, which hides every lost true positive.
The corrected values are the post-triage figures from
`testbed/reanalysis/reanalysis.json` (`ai_triage[*].fn_introduced`).
`AI_FP_Suppressed` counts suppressed tuples that are not ground-truth
positives, including 17 per run outside the scored set; the drop in scored
false positives is FP_pre - FP_post (14, 7, 7, 8).

## Superseded (2026-11-19)

`experiment_results_rev.csv` and `experiment_results_rep.csv` are graded on the
per-probe telemetry, which omits the LDAP- and NoSQL-injection testers (they
write no telemetry). The revised paper grades the full scan reports instead:
use `testbed/reanalysis/full_report_metrics.json` (`tools/full_report_metrics.py`)
for every TP/FP/precision/recall figure. The CSVs remain only as the telemetry
view used by the detection-cost analysis.
