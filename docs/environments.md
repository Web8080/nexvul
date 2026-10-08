# Environments: dev, staging, prod

nexvul is a local CLI, a PyPI package and a GitHub Action. It has no hosted backend, so an "environment" here is a
**release channel**: where a build is published, who may publish it, and who may consume it.

Status: **configured on GitHub, nothing is wired to it yet.** There is no package or workflow in the repo, so no
build has ever been published to any of these channels.

| | dev | staging | prod |
|---|---|---|---|
| Purpose | Every-commit builds for contributors and CI | Release candidates for dogfooding and benchmarking | Public releases |
| Source ref | Any branch or PR from this repo | `main` only | Tags matching `v*` only |
| Approval | None | None | Required reviewer (the maintainer) |
| Version form | `X.Y.Z.devN` | `X.Y.ZrcN` | `X.Y.Z` |
| Python package | Build artifact only, not published | TestPyPI | PyPI |
| GitHub Action ref | Not published | `@staging` moving tag | `@vX`, `@vX.Y.Z` |
| Docs | PR preview artifact | Not published | Public docs |
| Who consumes it | Contributors | The maintainers' own CI and the benchmark runs | Everyone |

The GitHub Environments `dev`, `staging` and `prod` exist on the repo with the branch and tag restrictions above.
The `prod` environment requires a reviewer. `prevent_self_review` is off for now because there is one maintainer;
turn it on when a second maintainer joins.

## Promotion rules

1. A change reaches **dev** automatically on every push and PR.
2. A change reaches **staging** by merging to `main`. Staging must pass the full test suite, the malicious-input
   suite, the SARIF validation and the benchmark regression gate before an rc is cut.
3. A change reaches **prod** only from a signed `v*` tag created from a commit that has already been through
   staging, and only after the reviewer approves the `prod` deployment. Publishing is by PyPI Trusted Publishing
   (OIDC) from the `prod` environment, with no long-lived API tokens stored in the repo.
4. Nothing is published to prod without the Release Engineer role's approval (brief §21).

## Secrets and trust

- Secrets are scoped per environment. `dev` has none. `staging` may hold only the TestPyPI trusted-publisher
  identity. `prod` holds the PyPI trusted-publisher identity.
- Prefer OIDC trusted publishing over stored tokens everywhere. If a token is unavoidable, it lives only in the
  `prod` or `staging` environment, never as a repository-wide secret.
- Workflows triggered from forks and `pull_request_target` never receive environment secrets. The release and
  supply-chain threats are T-26 to T-28 and requirement SR-26 in [threat-model.md](threat-model.md).
- Actions in release workflows are pinned to full commit SHAs, and the workflow's `permissions:` are minimal and
  declared per job.

## Decided (DEC-0006)

- **Staging and the Marketplace:** staging publishes only the `@staging` moving tag and the TestPyPI rc. The
  Marketplace listing is updated only from `prod`. Never reference `@staging` from a user workflow.
- **Docker:** no image for 1.0. The Action installs a hash-pinned release from PyPI. Revisit if users need
  hermetic or air-gapped CI.
- **Signing:** required from the first release candidate, not just prod: Trusted Publishing with PEP 740
  attestations, GitHub build-provenance attestations, a CycloneDX SBOM, signed tags, SHA-pinned actions.

## Not decided yet

- The release workflow itself. It is deliberately not written until there is a package to build.
