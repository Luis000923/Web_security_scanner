### Confusion matrix

| Outcome | Claims | Instances |
| --- | ---: | ---: |
| True positive (TP) | 409 | 182 |
| False negative (FN) | 12 | 12 |
| False positive (FP) | 46 | 15 |
| True negative (TN) | 129 | 129 |
| Reported, outside ground truth | 1 | -- |
| **Total** | **456** | **338** |

*TP/FP count *claims* (one per reported finding); FN/TN count *instances*. Rates whose denominator is a ground-truth population use the instance counts.*

`258` claim(s) landed on an instance that was already counted -- multi-tester overlap on the same endpoint.

### Rates

| Metric | Value |
| --- | ---: |
| Precision | 0.8969 |
| Recall | 0.9381 |
| F1 | 0.9171 |
| Specificity | 0.8958 |
| FPR (ground truth only) | 0.1042 |
| FP rate (over findings) | 0.1031 |
| Accuracy | 0.9201 |
| *TP_inst/(TP_inst+FN) over *measured* vulnerable instances; untested excluded* | |
| *TN/(TN+FP_inst) over labelled benign instances* | |
| *FP_inst/(FP_inst+TN) over labelled benign instances* | |
| *1 - precision; every reported finding in the denominator* | |
| *(TP_inst+TN)/total instances* | |

### Class agreement

The strictest reading of the same run: a detection counts only if the reported class is the one the labels expect. Every rate here is at or below its unqualified counterpart.

| Metric | Value |
| --- | ---: |
| Precision (class-matched) | 0.1820 |
| Recall (class-matched) | 0.4278 |
| F1 (class-matched) | 0.2554 |
| *class-matched claims / every claim; None when the labels carry no class* | |
| *class-matched instances / *class-labelled* vulnerable instances* | |
| *harmonic mean of the two class-matched rates* | |

`60` claim(s) landed on a class-labelled vulnerable instance with a reported type outside the shared vocabulary, so they are counted as mismatches rather than matches.

### Per-category breakdown

| Category | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| cmdi | 13 | 12 | 0 | 0 |
| ldapi | 6 | 0 | 0 | 0 |
| pathtraver | 30 | 0 | 0 | 0 |
| safe | 0 | 0 | 15 | 129 |
| sqli | 65 | 0 | 0 | 0 |
| xss | 68 | 0 | 0 | 0 |

<details><summary>1 finding(s) reported outside the ground truth (auditable list)</summary>

- `Missing Security Header https://127.0.0.1:8443/benchmark/cmdi-01/BenchmarkTest00907?BenchmarkTest00907=1`
</details>
