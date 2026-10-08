# nexvul — Benchmark Strategy

> Status: **Proposed** (Phase 0). Owner: 15 Benchmarking (Engineering Operations lead).
> Reviewers: 01 Principal Supervisor, 17 False Positive Hunter, 16 Adversarial Security.
> Binding: brief §5.15, §15, §21, §22–23, §32.7, §33. Related: `docs/test-strategy.md`, `docs/roadmap.md`,
> `benchmarks/schema/example.schema.json`.

## 1. Purpose and non-goals

The benchmark exists to answer, per rule and per revision: **how often is nexvul right, how often is it wrong, what
does it miss, and what does it cost to run** — with numbers that are reproducible and traceable.

Non-goals:
- It does **not** prove that a scanned project is secure, nor that a rule finds all instances of a weakness.
- It is **not** a marketing artefact. Numbers are published with method, raw data and known biases, or not at all.
- It is never optimised by deleting, relabelling or excluding inconvenient cases (brief §21, §23).

The competitive review notes that only one competitor publishes precision/recall and that it is self-labelled.
nexvul's answer is double-blind labelling, a held-out split, published raw data, and an invitation to external
labellers (Phase 7).

## 2. Corpus layout

```
benchmarks/
  schema/
    example.schema.json          # JSON Schema for case metadata (this repo)
  vulnerable/<RULE or ASI>/<case-id>/      # synthetic or derived code that SHOULD trigger
      case.yaml
      src/...
  safe/<RULE or ASI>/<case-id>/            # look-alike legitimate code that should NOT trigger
  frameworks/<framework>/<version>/<case-id>/   # idiomatic framework usage, both outcomes
  real_world/<project-slug>/
      case.yaml                  # pinned repo + commit; NO vendored source by default
      labels.yaml                # triaged findings + manually-reviewed regions
  adversarial/<RULE>/<case-id>/            # evasion attempts (aliases, wrappers, indirection…)
  perf/
      generator.py               # deterministic synthetic-repo generator (nexvul's own code)
      profiles.yaml              # 100 / 1k / 5k / 10k file profiles
  baseline/
      metrics.json               # last approved metrics, updated only by reviewed PR
  reports/<nexvul-version>-<git-sha>/      # generated, committed for releases only
```

Rules for the tree:
- `vulnerable/`, `safe/`, `adversarial/` and `frameworks/` contain **small, purpose-written** code under nexvul's own
  licence, or short derived snippets from allow-listed sources with attribution in `case.yaml`.
- `real_world/` contains **references, not copies** (§5).
- Held-out cases are **not** in this tree (§10).
- The whole `benchmarks/` tree is excluded from packaging, from pytest collection, from coverage, and from nexvul's
  own self-scan baseline (so intentionally vulnerable code never pollutes nexvul's results).

## 3. Case metadata schema

Every case has a `case.yaml`. Required fields are the brief §22 set (`name, source, framework, owasp,
expected_findings, expected_non_findings, license, notes`); the remaining fields make results traceable and
reviewable. The machine-checkable definition is `benchmarks/schema/example.schema.json` (JSON Schema 2020-12);
the harness validates every case before scoring and refuses to score an invalid corpus.

```yaml
# benchmarks/vulnerable/ASI06/web-to-vectorstore-001/case.yaml
schema_version: 1
id: BM-ASI06-0001                 # stable, never reused
name: "Fetched web page stored in vector store without validation"
category: vulnerable              # vulnerable | safe | frameworks | real_world | adversarial
language: python                  # python | javascript | typescript | config
split: dev                        # dev only in-repo; heldout lives elsewhere (§10)
source:
  kind: synthetic                 # synthetic | derived | external_ref
  # for derived / external_ref:
  # repo: https://github.com/<owner>/<repo>
  # commit: <40-hex sha>
  # path: <path within repo>
  # retrieved: 2026-10-08
framework:
  name: langchain                 # or "none"
  version: "unverified"           # exact version the case was written against, or "unverified"
owasp: [ASI06]
cwe: []                           # only where a defensible mapping exists
expected_findings:
  - rule: NEX001                  # final IDs from docs/detection-taxonomy.md
    file: src/ingest.py
    line: 12                      # sink line; may use line_range: [12, 14]
    severity: high
    confidence: high
    flow:                         # optional: expected evidence chain, checked if present
      - {file: src/ingest.py, line: 9,  role: source}
      - {file: src/ingest.py, line: 12, role: sink}
expected_non_findings:
  - rule: NEX001
    file: src/ingest.py
    line: 20
    reason: "Content passes through allow-listed validator before storage"
license:
  spdx: Apache-2.0                # licence of THIS case's files (nexvul's licence for synthetic)
  attribution: null
labels:
  author: "15-benchmarking"
  labelled_by: ["17-fp-hunter", "02-security-research"]   # two independent labellers
  adjudicated_by: "01-principal-supervisor"               # only if labellers disagreed
  review_ids: [REV-0007]
tags: [intra-procedural, requests, vector-store]
notes: >
  Minimal positive. Does not cover async fetch (see BM-ASI06-0004).
```

## 4. Corpus composition targets (per shipped rule)

Proposed minimums before a rule can leave Phase 2 (Supervisor approves; raise later as the corpus grows):

| Category | Minimum per rule | Purpose |
|----------|------------------|---------|
| vulnerable | 10 cases | Recall on known-bad patterns |
| safe | 15 cases | Look-alikes; FP measurement (more negatives than positives on purpose) |
| adversarial | 8 cases | Evasion: alias, wrapper, indirection, dynamic import, decorator, inheritance, callback, async, renamed module, obfuscated strings, config change, framework abstraction |
| frameworks | 2 per framework the rule claims | Framework-idiomatic code |
| real_world | ≥ 3 projects scanned and triaged | Precision in the wild |
| held-out | ≥ 20% of the total above, kept separately | Overfitting check |

Adversarial cases that nexvul **knowingly misses** stay in the corpus with `expected_findings` filled in. They
count as FN. That is how known limitations remain visible.

## 5. Licence policy

**Allow-list** (code may be referenced, and short derived snippets may be adapted with attribution):
MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, Unlicense, CC0-1.0, Python-2.0 (PSF), Zlib.

**Restricted** (reference by pinned commit only for local measurement; no derived snippets in-repo; human approval
needed per project): MPL-2.0, EPL-2.0, LGPL-*, CC-BY-4.0 (often used for docs only — check whether code has a
separate licence).

**Denied** (do not reference, do not fetch into CI): GPL-*, AGPL-*, SSPL, BUSL/BSL, Polyform (any variant),
Elastic License, Commons Clause, "source-available", **no licence file**, custom/unclear licences.

Process:
1. Check the repository's root licence file **and** any subdirectory licence files (mixed-licence repos exist —
   see AutoGPT and MCP in §11). Record exactly what was checked and when in `case.yaml`.
2. Any ambiguity ⇒ treat as denied and escalate (brief §32.7). Agents may not decide unclear licences.
3. **Pinned commit refs, not vendoring.** `real_world/` stores `repo`, `commit` (full 40-hex SHA), `paths` of
   interest and labels — not the source. The fetcher retrieves that exact commit into a cache outside the repo.
4. Vendoring is allowed only for a small, allow-listed, attributed excerpt needed as a stable regression fixture
   (moved to `vulnerable/`/`safe/` as `source.kind: derived`), with the upstream licence text preserved alongside.
5. Licence status is re-checked when a pinned commit is bumped.

## 6. Never execute benchmark code

Benchmark code is hostile data, the same as any scanned repo (brief §0, §2):

- The harness only **reads** files and invokes nexvul. It never imports, runs, installs or builds corpus code.
- Fetching real-world projects: `git` with hooks disabled (`-c core.hooksPath=/dev/null`), no submodule recursion,
  `GIT_LFS_SKIP_SMUDGE=1`, no `filter`/`textconv` drivers, fetch by SHA, verify SHA after fetch, cache outside the
  working tree, no `pip install`/`npm install`, no `setup.py`, no notebooks executed.
- pytest is configured with `collect_ignore_glob` for `benchmarks/**`, and corpus files never use `test_*.py` /
  `*_test.py` / `conftest.py` names (see test-strategy §4.1 — a fixture named `test_x.py` would be **executed** by
  pytest).
- CI benchmark jobs run with no secrets in the environment and network disabled after the fetch step.
- A test asserts that a sentinel file in the corpus (which would write a marker if executed) is never executed
  during a benchmark run.

## 7. Ground-truth labelling

1. **Author** writes the case and a proposed label.
2. **Two independent labellers** (different roles, neither the rule author — e.g. 17 FP Hunter and 02 Security
   Research or the domain agent) label without seeing each other's label or nexvul's output for that case.
3. Agreement ⇒ label accepted. Disagreement ⇒ **adjudication** by the Principal Supervisor; the reasoning is
   recorded in a review artefact (`REV-NNNN`). Persistent disagreement on OWASP mapping escalates (brief §32.3).
4. Inter-labeller agreement (Cohen's κ) is reported per category in each benchmark report.
5. Real-world labelling: nexvul's findings are triaged into TP / FP / acceptable warning / needs context
   (brief §5.17) using `.nexvul/templates/fp-triage.md`. To estimate recall on real code, labellers also
   **manually review a sampled set of files** blind to nexvul output and record every true instance they find;
   recall is reported **only** over those reviewed regions, and the report says so.
6. Labels are never changed to make a rule pass. A label change requires a review artefact with a reason that
   would be valid if the rule did not exist.

"Acceptable warning" and "needs context" are counted separately and reported; for the precision gate they count
as FP unless the rule's documentation explicitly scopes them as intended behaviour (decided at rule approval).

## 8. Metrics

### 8.1 Detection metrics (per rule, per category, per split, per language)

- **Matching**: a finding matches an expected finding when `rule` and `file` are equal and the reported sink line is
  within `line` or `line_range`. If `flow` is specified, the source step must also match (a correct sink with a wrong
  source is reported as `TP-wrong-evidence` and counted as FP for precision until fixed).
- **TP** matched expected findings. **FN** expected findings with no match. **FP** findings matching no expected
  finding in a fully-labelled case, or matching an `expected_non_findings` entry. Duplicate findings for one
  expected item count one TP; extras are reported as `duplicates` (counted FP).
- **Precision** = TP/(TP+FP); **Recall** = TP/(TP+FN); **F1** = 2PR/(P+R). Each reported with counts and a 95%
  Wilson interval; a metric with fewer than 10 observations is marked *insufficient data*.
- Also reported: findings per 10k LOC on `real_world/` (noise indicator), severity/confidence distribution,
  κ agreement, list of every FN and FP case ID (not just totals).

### 8.2 Performance metrics

Measured on deterministic synthetic repositories from `benchmarks/perf/generator.py` at **100 / 1,000 / 5,000 /
10,000 files** (brief §15), plus each `real_world/` project:

| Metric | How |
|--------|-----|
| Wall-clock runtime | `time.perf_counter`, median and p90 of 5 runs after 1 warm-up |
| CPU time | `resource.getrusage` user+sys |
| Peak RSS | `ru_maxrss` of the child process (normalise units: bytes on macOS, KiB on Linux) |
| Files/sec | files analysed ÷ wall time |
| Findings | count by rule (sanity check that perf runs are not silently skipping work) |
| Cache effect | cold vs warm run |

Runner spec (CPU model, cores, RAM, OS, Python version) is recorded in every report. Cross-machine numbers are
never compared directly.

### 8.3 Proposed false-positive budget — **REQUIRES HUMAN APPROVAL**

These are proposals to start discussion, not facts about any tool. Precision is measured on `safe/ + vulnerable/ +
adversarial/ + real_world/` combined, **and** separately on the held-out set.

| Confidence | Severity | Min precision (dev) | Min precision (held-out) | High-confidence FPs on `safe/` | CI default |
|-----------|----------|---------------------|--------------------------|--------------------------------|-----------|
| high | critical / high | 0.90 | 0.85 | 0 | fails build at `fail-on: high` |
| high | medium / low | 0.85 | 0.80 | ≤ 1 per rule | reported |
| medium | any | 0.75 | 0.70 | n/a | reported, does not fail by default |
| low | any | 0.50 | — | n/a | **off by default**; opt-in only |

Additional proposals:
- Real-world noise ceiling: ≤ 1 high-confidence FP per 100k LOC scanned across `real_world/`.
- Minimum recall for shipping is deliberately modest (≥ 0.60 on `vulnerable/`), because brief §5.15 prioritises
  trust over recall — but every FN is listed in the report and in `docs/rules/<RULE>.md`.
- A rule that misses its budget follows brief §23: improve semantics → add context → reduce scope → lower
  confidence → don't ship. **Hiding findings or excluding cases is not an option.**

The human may tighten or loosen these. Until approved, Phase 2 cannot exit (roadmap §2).

## 9. CI regression gating

| Trigger | Runs | Blocks merge when |
|---------|------|-------------------|
| Every PR | schema validation; `vulnerable/`, `safe/`, `adversarial/`, `frameworks/`; perf at 100 & 1k | any previously-passing expected finding becomes FN; any new FP on `safe/`; a rule drops below its approved budget; schema invalid; perf median regresses > 25% at 1k (proposed, noisy runners need a re-run rule) |
| Nightly | above + `real_world/` (pinned fetch) + perf 5k & 10k | does not block; opens an issue/FND artefact on regression |
| Release | everything + held-out evaluation by 15 Benchmarking | any gate fails ⇒ no release |

- `benchmarks/baseline/metrics.json` is the comparison point. It changes **only** in a PR that includes the new
  report, a reviewer who is not the change author, and a `REV-NNNN` reference.
- Improvements are locked in: once a case passes, it is a regression test forever.
- A failing benchmark case may not be deleted, skipped or `xfail`-ed to unblock a merge (brief §21). The allowed
  route is a documented known-limitation entry approved by the Supervisor, with the case still counted as FN/FP.

## 10. Held-out set (anti-overfitting)

- Each new case is assigned to `dev` or `heldout` by the Benchmarking agent at creation time (deterministic hash of
  the case ID; target 20–25% held-out per rule and category).
- Held-out cases live **outside the public repository**, in a location controlled by the human product owner
  (proposal: a private repository or local directory). Rule authors and rule-implementing agents never see their
  contents — only aggregate per-rule scores. **Decision needed from the human (§32.1)** on where this lives; until
  then, held-out cases are stored in a separate directory that rule-implementing agents are instructed not to read,
  and this weaker protection is stated in every report.
- Held-out evaluation runs only at phase exits and releases, by 15 Benchmarking.
- A dev/held-out gap larger than 0.10 in precision or recall for a rule is treated as overfitting and blocks that
  rule.
- After each minor release, the used held-out set is **retired into dev** (published) and a fresh held-out set is
  written. Reports state which held-out generation was used.

## 11. Verified candidate list — real OSS agent projects

Verified 2026-10-08 via the GitHub REST API (licence SPDX as detected by GitHub) and, where flagged, by reading the
licence file. "HEAD observed" is the default-branch commit seen on that date via `git ls-remote`; it is the
**proposed pin**, to be confirmed by the Benchmarking agent at onboarding. No repository below has yet been scanned
or labelled; nothing here is a finding about these projects.

**Role**: *App* = an agent application (best for realistic precision/recall); *Lib/Examples* = a framework or SDK,
used mainly for FP measurement on large idiomatic code and for its example directories.

| Project | Role | Lang | Licence (verified) | Status | HEAD observed | Relevant ASI |
|---------|------|------|--------------------|--------|---------------|--------------|
| `langchain-ai/langchain` | Lib/Examples | Py | MIT | allow | `1f587e3f4e0b` | 06, 09, 10 |
| `langchain-ai/langgraph` | Lib/Examples | Py | MIT | allow | `40a2e6d84505` | 08, 09 |
| `langchain-ai/langchainjs` | Lib/Examples | TS | MIT | allow | `aa1b519f91b2` | 06 (JS/TS) |
| `langchain-ai/langgraphjs` | Lib/Examples | TS | MIT | allow | `37d863e7e9d7` | 08 (JS/TS) |
| `langchain-ai/open_deep_research` | App | Py | MIT (repo archived) | allow | `1b7d2e80db9f` | 06, 08 |
| `langchain-ai/langchain-mcp-adapters` | Lib | Py | MIT (repo archived) | allow | `52a4535f3eb4` | 07 |
| `crewAIInc/crewAI` | Lib/Examples | Py | MIT | allow | `42ae4bf2c05f` | 08, 10 |
| `microsoft/autogen` | Lib/Examples | Py | Code: MIT (`LICENSE-CODE`); docs: CC-BY-4.0 (`LICENSE`) — GitHub reports CC-BY-4.0 | allow for code only | `027ecf0a379b` | 07, 08 |
| `openai/openai-agents-python` | Lib/Examples | Py | MIT | allow | `26345c1e45eb` | 09, 10 |
| `openai/openai-agents-js` | Lib/Examples | TS | MIT | allow | `05241c7aa3d5` | 09, 10 (JS/TS) |
| `modelcontextprotocol/python-sdk` | Lib | Py | MIT | allow | `91941ed4d398` | 07 |
| `modelcontextprotocol/typescript-sdk` | Lib | TS | Mixed MIT / Apache-2.0 (licence transition stated in `LICENSE`) | allow (both permissive); record as mixed | `b022522089a0` | 07 |
| `modelcontextprotocol/servers` | App (reference servers) | TS/Py | Mixed MIT / Apache-2.0 (same transition) | allow; record as mixed | `5abed86c5317` | 07, 10 |
| `a2aproject/a2a-python` | Lib | Py | Apache-2.0 | allow | `494a8ece0ad9` | 07 |
| `a2aproject/a2a-samples` | App (samples) | Py/nb | Apache-2.0 | allow (skip notebooks unless parsed statically) | `6603ba3f2c31` | 07 |
| `assafelovic/gpt-researcher` | App | Py | Apache-2.0 | allow | `0957c301ed06` | 06, 08 |
| `stanford-oval/storm` | App | Py | MIT | allow | `fb951af7744d` | 06 |
| `FoundationAgents/MetaGPT` (moved from `geekan/MetaGPT`) | App | Py | MIT | allow | `11cdf466d042` | 07, 08 |
| `browser-use/browser-use` | App | Py | MIT | allow | `c75e8476e26d` | 06, 09, 10 |
| `huggingface/smolagents` | Lib/Examples | Py | Apache-2.0 | allow | `96f33faaf028` | 10 |
| `pydantic/pydantic-ai` | Lib/Examples | Py | MIT | allow | `f55bb8a6fd6c` | 09, 10 |
| `run-llama/llama_index` | Lib/Examples | Py | MIT | allow | `cb4c917ffe8c` | 06 |
| `mem0ai/mem0` | Lib (memory layer) | Py | Apache-2.0 | allow | `b7ad69afda6b` | 06 |
| `letta-ai/letta` | App (stateful agents) | Py | Apache-2.0 | allow | `5bcdd177d70f` | 06 |
| `agno-agi/agno` | Lib/Examples | Py | Apache-2.0 (as reported by GitHub) | allow — re-check licence file at onboarding | `718ae26fb90f` | 06, 10 |
| `OpenHands/OpenHands` (moved from `All-Hands-AI/OpenHands`) | App | Py/TS | MIT (root, as reported by GitHub) | allow — **check subdirectory licences** at onboarding | `baf1cbef090f` | 09, 10 |

Checked and **excluded** (or restricted):

| Project | Reason |
|---------|--------|
| `crewAIInc/crewAI-examples` | No licence file (`LICENSE` 404 on default branch; GitHub reports none) ⇒ denied |
| `Significant-Gravitas/AutoGPT` | Mixed: `autogpt_platform/` is Polyform Shield (denied); remainder MIT. Excluded unless the human approves a path-restricted reference to the MIT part |
| `openinterpreter/openinterpreter` (moved from `OpenInterpreter/open-interpreter`) | Apache-2.0, but GitHub now reports primary language Rust — out of language scope; re-evaluate if a Python release branch is pinned |
| `microsoft/TaskWeaver` | MIT but archived; low priority |
| `microsoft/semantic-kernel` | MIT but primary language C# — out of scope |

Full SHAs are recorded in `.nexvul/tasks/` onboarding tasks when each project is added; abbreviated SHAs above are
for readability only.

## 12. Reporting

Each benchmark report (`benchmarks/reports/<version>-<sha>/`) contains: `metrics.json` (machine-readable),
`report.md` (human-readable, generated), the exact nexvul version and git SHA, corpus revision, held-out generation
(if evaluated), runner spec, per-rule tables, every FP/FN case ID with a one-line reason, κ agreement, perf tables,
and a **Limitations** section (self-labelled data, corpus size, synthetic bias, languages covered). Reports are
generated, never hand-edited. Publication of a report outside the repo requires Supervisor approval.

## 13. Open decisions for the human

1. Approve or amend the FP budget (§8.3).
2. Where the held-out set lives (§10).
3. Whether to allow path-restricted use of mixed-licence repos (AutoGPT MIT part) (§11).
4. Whether to invite external labellers in Phase 7 and under what terms.
