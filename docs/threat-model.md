# Threat Model

## Assets

- host integrity and availability;
- source-code confidentiality;
- API credentials and provider budgets;
- report integrity and benchmark reproducibility.

## Trust boundaries

Repository files, names, links, encodings, comments, and embedded instructions are untrusted. Provider responses are also untrusted until schema and evidence-reference validation succeeds. CLI options and local configuration are operator-controlled but still validated.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Target code execution | No imports, builds, installs, tests, hooks, or target commands | Parser/library defects remain possible |
| Path or symlink escape | Resolved-root containment, no link following, reparse-point rejection | Filesystem races are reduced, not formally eliminated |
| Resource exhaustion | File count, depth, total bytes, per-file bytes, bounded snippets and provider context | Adversarial syntax can still consume parser CPU within process limits |
| Source disclosure | Offline default; explicit Agent mode; minimal redacted evidence | Enabled external providers receive selected snippets |
| Prompt injection in source | Source is quoted as data; fixed role contracts; structured validation | A model may still produce unusable output, which becomes `needs_review` |
| Credential leakage | API key is read from a named environment variable and never serialized | Operator shell history and external provider handling are out of scope |
| Report XSS | HTML autoescaping; no execution of repository content | Browser or template engine vulnerabilities are out of scope |
| Budget abuse | Request, token, context-byte, and USD checks before calls | Misconfigured zero prices understate provider billing |
| Benchmark gaming | Independent truth manifest, safe near-misses, deduplication, repeatable offline score | Bundled corpus is small and cannot represent all real projects |
| Report overwrite in target | Outputs inside scanned source are rejected except ignored artifact directories | Operator can explicitly choose an external path with its own permissions |

## Non-goals

AegisFlow does not attack services, execute proof-of-concept payloads, modify target source, guarantee exploitability, detect every CWE, or serve as a sandbox for hostile code. Findings require human review before disclosure or production action.

