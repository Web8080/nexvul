# FND-NNNN: Adversarial report — <rule ID or component>

| Field | Value |
|-------|-------|
| Status | new \| triaged \| confirmed \| fixed \| verified \| wont_fix \| accepted_risk |
| Target | NEXNNN \| component (discovery, parser, config, reporter, …) @ git SHA |
| Tester | 16 Adversarial Security |
| Date | YYYY-MM-DD |
| Scope | detection evasion \| hostile input against nexvul \| both |

## Part A — Detection evasion (brief §5.16)

| # | Technique | Fixture path | Detected? | Expected? | Action |
|---|-----------|--------------|-----------|-----------|--------|
| 1 | Alias import (`import x as y`) | | yes/no | | test added / known miss FND |
| 2 | Wrapper / helper function | | | | |
| 3 | Indirection via dict / attribute / container | | | | |
| 4 | Dynamic import (`importlib`, `__import__`) | | | | |
| 5 | Decorator | | | | |
| 6 | Inheritance / method override | | | | |
| 7 | Callback / higher-order function | | | | |
| 8 | Async / await / task groups | | | | |
| 9 | Renamed module / re-export | | | | |
| 10 | Obfuscated strings (concat, f-string, encoding) | | | | |
| 11 | Configuration change (YAML/env-driven) | | | | |
| 12 | Framework abstraction (chains, graphs, crews) | | | | |
| 13 | Cross-file split of source and sink | | | | |
| 14 | Other: | | | | |

## Part B — Hostile input against nexvul (brief §2, §19)
Cases tried (giant files, nesting, symlinks, traversal names, malicious config, ReDoS, unicode, binary,
prompt-injection text in comments, malformed manifests, output-injection into SARIF/HTML…), result and
regression-test path for each. **Vulnerabilities in nexvul itself go to `.nexvul/security/`, not here.**

## Summary
- Evasions found: N (fixed: N, documented known misses: N)
- Regression tests added: paths
- Recommended confidence/scope changes:

## Comments
