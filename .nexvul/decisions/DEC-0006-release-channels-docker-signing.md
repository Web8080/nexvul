# DEC-0006: Staging Marketplace pre-release, Docker image, signing

| Field | Value |
|-------|-------|
| Status | accepted |
| Decider | Human product owner, delegated to the Supervisor ("mk the call") |
| Proposed by | 21 Release Engineer / docs/environments.md |
| Date decided | 2026-10-08 |
| Links | docs/environments.md; docs/threat-model.md T-26..T-28, SR-26 |

## 1. Staging and the GitHub Marketplace
**Decision:** staging does **not** publish a Marketplace listing or pre-release. Staging publishes only the moving
`@staging` tag of the Action (and the rc package to TestPyPI). The Marketplace listing is created and updated only
from `prod`, on a `v*` release.
**Why:** a Marketplace listing is public and sticky; a moving tag is enough for our own CI to dogfood a candidate.
**Note:** `@staging` is a mutable tag. Our own workflows may use it; docs must tell users never to (threat T-27).

## 2. Docker image
**Decision:** not now. No Docker image for 1.0.
**Why:** the scanner is a pure-Python wheel; a composite Action that installs a **hash-pinned** release from PyPI
gives CI users a reproducible run without a second artifact to sign, scan and keep patched. A container adds a base
image supply chain and no capability we need.
**Revisit when:** users need hermetic or air-gapped CI runs, or a native dependency (e.g. a tree-sitter wheel)
makes pip installs unreliable. If revisited, it follows the same three channels and the same signing rules.

## 3. Signing and provenance
**Decision:** required from the **first staging release candidate**, so the prod release is not the first time the
pipeline runs.
- PyPI and TestPyPI publishing by Trusted Publishing (OIDC) with PEP 740 attestations enabled.
- GitHub artifact attestations (build provenance) for the sdist, wheel and SBOM.
- CycloneDX SBOM attached to every release.
- Release tags are signed; the prod environment refuses unsigned tags.
- Build dependencies hash-pinned; release workflows pin actions by full commit SHA with minimal per-job permissions.
- The release docs show how users verify a download.
**Why:** a security scanner that cannot prove where it came from is itself a supply-chain risk (T-28, SR-26).

## Reversibility
All three are reversible. Docker and a Marketplace pre-release can be added later; signing is the one item that
must not be dropped.
