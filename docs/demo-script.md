# Five-Minute Demo Script

## 0:00-0:40 - Safety and environment

Run `aegisflow doctor`. State that repositories are parsed as hostile, read-only data: no target import, execution, build, install, tests, hooks, or network access in offline mode.

## 0:40-1:10 - Rule depth

Run `aegisflow rules --format table`. Show the four deliberately narrow high-impact classes and explain that the project prioritizes source-to-sink evidence and suppressors over a large shallow rule count.

## 1:10-2:20 - Offline scan

```powershell
aegisflow scan .\benchmarks\fixtures --mode offline --format html --output .\artifacts\report.html --fail-on none
```

Open the report. Select one command-injection finding and point out the source, propagation, sink, confidence, stable fingerprint, remediation, and deterministic Scout/Tracer decisions. Then show a safe parameterized SQL or basename case that did not become a finding.

## 2:20-3:20 - Reproducible metrics

```powershell
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```

Show precision, recall, F1, false-positive rate, scanned lines, elapsed time, and time to first high. Explain the independent truth manifest and paired near-miss files. State clearly that the score applies only to this versioned corpus.

## 3:20-4:20 - Agent workflow and cost control

Show `config/model.example.toml`. Explain the route: complete local evidence is confirmed offline; safe evidence is rejected; only ambiguous high-risk candidates may enter Verifier, Critic, and Arbiter review. Point to hard request, token, context, and USD budgets. Do not enable a live provider unless explicit approval and credentials are available.

## 4:20-5:00 - Repeatability and scope

Run the offline scan a second time and compare normalized finding IDs. Close with the honest boundary: local bounded taint tracking for Python and JS/TS, not whole-program analysis, runtime reachability, binary analysis, active exploitation, or automated source modification.

