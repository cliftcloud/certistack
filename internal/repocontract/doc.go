// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package repocontract has no code of its own. Its tests check that what ships
// around the Go code says what the code does: the documentation (links,
// commands, environment variables, plan fields, the report schema, the editions
// table, supported versions, examples), the GitHub workflows, the container
// image and release build, the Terraform module, the appliance's Packer recipe
// and guide, the installer script, license headers and third-party notices,
// and the public contact addresses. They parse the files and run their shell
// against local stubs. Nothing they run reaches a network, registry or PVE
// node.
package repocontract
