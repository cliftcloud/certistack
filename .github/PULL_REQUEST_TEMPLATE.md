<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2024-2026 Clift Cloud LLC
-->
## What and why

<!-- One or two sentences on the problem and the approach. Link the issue. -->

## Safety

- [ ] The change does not weaken a [safety guarantee](https://certistack.dev/docs/#safety): read-only backups, an isolated sandbox, explicit pass and fail rules, verified cleanup and journal-scoped recovery, a report of every run.
- [ ] No credential, repository string, private key path, real host name or report from a real environment is included.
- [ ] New or changed plan fields are documented under "The keys" in `docs/plan-reference.md`.

## Checks

- [ ] `make test`, `go test -race ./...`, `make fmt-check` and `make vet` pass locally.
- [ ] Documentation is updated where behaviour changed (`docs/`, `README.md`, CLI help text).
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`.

## CLA

- [ ] I have signed the [Contributor License Agreement](../blob/main/CLA.md), or will reply to the CLA bot's comment on this pull request.
