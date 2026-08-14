# Benchmark Methodology

## Corpus

The bundled corpus contains 16 independent files: one vulnerable and one structurally related safe case for each of four vulnerability classes in Python and JavaScript. Eight vulnerable cases appear in `benchmarks/ground_truth.json`; safe cases do not contain expected entries.

| Rule | CWE | Python | JavaScript |
|---|---|---:|---:|
| `AF-CMD-001` | CWE-78 | vulnerable + safe | vulnerable + safe |
| `AF-SQL-001` | CWE-89 | vulnerable + safe | vulnerable + safe |
| `AF-PATH-001` | CWE-22 | vulnerable + safe | vulnerable + safe |
| `AF-DESER-001` | CWE-502 | vulnerable + safe | vulnerable + safe |

The safe near-misses exercise constant commands, parameterized SQL, basename path reduction, and data-only JSON parsing. Expected results are kept outside source comments to avoid trivial fixture coupling.

## Scoring

A true positive requires the same rule ID, normalized repository-relative path, and an overlapping line range. Duplicate finding fingerprints count once. Unmatched report findings are false positives; unmatched truth entries are false negatives.

```text
precision = TP / (TP + FP)
recall = TP / (TP + FN)
F1 = 2 * precision * recall / (precision + recall)
false-positive rate = FP / (TP + FP)
```

The report also records files and lines scanned, elapsed time, time to first high-severity finding, candidate and disposition counts, human-review count, provider requests, tokens, and estimated USD cost.

## Reproduction

```powershell
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```

Record AegisFlow version, Python version, operating system, processor, run configuration, and whether Agent mode was enabled. The offline run is canonical. Agent-assisted changes must be reported separately because model versions and outputs can vary.

## Interpretation limits

This is a small regression and demonstration corpus, not an estimate of universal real-world accuracy. It primarily proves that the declared rules detect representative local flows and suppress paired near-misses. Claims should be expanded only with versioned public corpora and a held-out set that was not used to tune rules.

