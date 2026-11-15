<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2024-2026 Clift Cloud LLC
-->
## What and why

<!-- One or two sentences on the problem and the approach. Link the issue. -->

## Safety review

- [ ] The change does not weaken a guarantee in README.md ("What it does": read-only sources, an isolated network, checks with explicit pass or fail rules, cleanup and journal-scoped recovery, a report of every run).
- [ ] No credential, repository string, private-key path, real hostname, or report from a real environment is included.
- [ ] New or changed plan fields are documented under "The keys" in `docs/plan-reference.md`.

## Verification

- [ ] `make test`, `go test -race ./...`, `make fmt-check`, and `make vet` pass locally.
- [ ] Documentation updated where behaviour changed (`docs/`, `README.md`, CLI help text).
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`.

## CLA

- [ ] I have signed the [Contributor License Agreement](../blob/main/CLA.md), or will reply to the CLA bot's comment on this pull request.
