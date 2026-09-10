# Threats to validity — machine-level latency bias on the OWASP Benchmark testbed

The empirical evaluation in this repository grades the DAST scanner against
**OWASP Benchmark 1.2** (`testbed/docker-compose.yml` → `owasp/benchmark`, a
Java/Spring application on an embedded Tomcat, `MAVEN_OPTS=-Xmx1g`). Two
properties of the Java Virtual Machine bias the scanner's **time-based**
injection detection (SQL injection and command injection). This document records
the threats and the mitigations now implemented in the engine and the
experiment scripts.

---

## T1 — Cold JVM / JIT warm-up

**Threat.** The first requests to a given endpoint run interpreted bytecode; the
HotSpot JIT only compiles a method to native code after it has been invoked
enough times. Early responses can be several times slower than steady state.
Because `tools/run_experiments.py` enqueues targets through `--target-list`
(recon skipped) and each tester captures its latency baseline immediately,
those baselines were sampled while the endpoint was still cold — inflated and
high-variance — which both raises the time-based threshold (masking real
findings) and, on a subsequent GC-quiet fast response, can look like a negative
delta.

**Mitigation — explicit warm-up phase.**
`AsyncScannerCore.warmup(url, n)` fires `n` discard requests per endpoint
(identity key `scheme://netloc/path`) **before** any baseline or telemetry
capture. It is:

* idempotent per endpoint — a per-injection-point warm-up inside a tester
  (`VulnerabilityTester.warmup_point`) and the orchestrator's per-target
  pre-warm (`WebSecurityScanner._warmup_targets`) never double-fire;
* routed through `AsyncScannerCore.request(use_cache=False)`, so the **token
  bucket, concurrency semaphore and SSRF guard still apply**;
* silent in the telemetry — warm-up requests emit no JSONL rows, so
  `request_index` and per-budget cost accounting are unaffected.

**Controls.**

| Knob | Where | Default |
|---|---|---|
| `--warmup N` | `webscanner scan` | `0` (opt-in) |
| `--warmup N` | `tools/run_experiments.py` | `20`, applied uniformly to every condition |
| `testers.warmup_requests` | config / reproducibility manifest | mirrors the flag |

Warm-up is a **machine-bias control, not an ablation axis**: it is applied
identically to every budget × condition cell, so it removes a confound without
affecting the relative comparison between conditions.

---

## T2 — Garbage-collector pause jitter

**Threat.** Stop-the-world GC pauses inject random multi-hundred-millisecond
spikes into response latency. With only a handful of baseline samples, the old
trigger `mean + 3·pstdev(samples) − min` was swung by a single spike (one slow
sample inflates both the mean and the standard deviation → real time-based hits
suppressed) or by a single unusually fast sample (deflates the estimate → benign
GC jitter trips a false positive).

**Mitigation — robust variance with a rolling window.**

* `VulnerabilityTester.adaptive_time_threshold()` now uses
  **`median + σ·1.4826·MAD − min`** (MAD = median absolute deviation;
  `1.4826` is the normal-consistency constant). Median and MAD each ignore a
  single outlier in either direction.
* `RollingLatency` keeps a bounded window (`--latency-window`, default 12) of the
  most recent **benign** probe latencies. Testers feed every non-firing probe's
  `elapsed` via `observe_latency()`, so the bar re-estimates itself mid-sweep as
  the JVM warms further or GC pressure changes.
* More baseline samples are cheap after warm-up: `--baseline-samples` (default
  `3`) is now configurable.

**Controls.** `--baseline-samples N`, `--latency-window N`, and the module
constants `TIME_BASED_SIGMA = 3.0`, `TIME_BASED_THRESHOLD = 4.0` (the absolute
floor, unchanged).

---

## T3 — Single-shot confirmation landing on a GC pause

**Threat.** `confirm_time_based()` previously replayed each variant once. A GC
pause coinciding with that single replay produced a spurious `CONFIRMED`.

**Mitigation — every stage must reproduce.** `confirm_time_based(replays=2)`
samples each stage twice and requires the delay to reproduce on **all** replays:

1. reduced-delay variant (`SLEEP(5)` → `SLEEP(2)`): both replays must track
   `baseline + ~2 s` → the delay scales with the attacker-controlled value →
   `CONFIRMED`;
2. otherwise the original payload: `CONFIRMED` only if the **minimum** of the two
   replay latencies clears *both* `baseline + threshold` *and* the rolling
   robust upper bound. `min` means one GC pause on either replay cannot confirm;
3. otherwise `LOW`.

---

## Residual threats

* **Shared host contention.** The scanner runs on the host, the testbed in
  Docker; other host load still adds noise. Mitigated only partially by the
  robust statistics above — run the sweep on an otherwise-idle machine.
* **GC pause exceeding the confirmation window.** A pause longer than the whole
  two-replay confirmation would still bias it; in practice `-Xmx1g` young-gen
  pauses are well under the `SLEEP(2..5)` payload deltas.
* **Warm-up depth.** `N = 20` empirically reaches the JIT C2 tier for the
  Benchmark servlets; a much larger corpus of endpoints per run may need a
  higher `N`.

---

## Reproducing / auditing the mitigations

* Every run's `manifest_<run_id>.json` records the exact
  `testers.warmup_requests` / `baseline_latency_samples` / `latency_window`.
* `tools/analyze_results.py` emits a `bias_mitigations` block into
  `testbed/analysis/stats.json`: the static description above **plus** the
  observed per-run knobs, and a `notes` entry for any run that executed with
  `warmup_requests == 0`.
* A/B: run one sweep with `--warmup 0` and one with `--warmup 20`; compare the
  first-N `elapsed_time` values per endpoint in the telemetry JSONL and the
  time-based precision in the graded CSV.
