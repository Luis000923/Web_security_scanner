### Confusion matrix

| Outcome | Claims | Instances |
| --- | ---: | ---: |
| True positive (TP) | 135 | 135 |
| False negative (FN) | 59 | 59 |
| False positive (FP) | 1 | 1 |
| True negative (TN) | 143 | 143 |
| Reported, outside ground truth | 1 | -- |
| **Total** | **137** | **338** |

*TP/FP count *claims* (one per reported finding); FN/TN count *instances*. Rates whose denominator is a ground-truth population use the instance counts.*

### Rates

| Metric | Value |
| --- | ---: |
| Precision | 0.9854 |
| Recall | 0.6959 |
| F1 | 0.8157 |
| Specificity | 0.9931 |
| FPR (ground truth only) | 0.0069 |
| FP rate (over findings) | 0.0146 |
| Accuracy | 0.8225 |
| *TP_inst/(TP_inst+FN) over *measured* vulnerable instances; untested excluded* | |
| *TN/(TN+FP_inst) over labelled benign instances* | |
| *FP_inst/(FP_inst+TN) over labelled benign instances* | |
| *1 - precision; every reported finding in the denominator* | |
| *(TP_inst+TN)/total instances* | |

### Class agreement

The strictest reading of the same run: a detection counts only if the reported class is the one the labels expect. Every rate here is at or below its unqualified counterpart.

| Metric | Value |
| --- | ---: |
| Precision (class-matched) | 0.8978 |
| Recall (class-matched) | 0.6340 |
| F1 (class-matched) | 0.7432 |
| *class-matched claims / every claim; None when the labels carry no class* | |
| *class-matched instances / *class-labelled* vulnerable instances* | |
| *harmonic mean of the two class-matched rates* | |

### Per-category breakdown

| Category | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| cmdi | 25 | 0 | 0 | 0 |
| ldapi | 6 | 0 | 0 | 0 |
| pathtraver | 30 | 0 | 0 | 0 |
| safe | 0 | 0 | 1 | 143 |
| sqli | 65 | 0 | 0 | 0 |
| xss | 9 | 59 | 0 | 0 |

<details><summary>1 finding(s) reported outside the ground truth (auditable list)</summary>

- `synthetic-outside /not/covered/by/ground-truth?zz`
</details>
