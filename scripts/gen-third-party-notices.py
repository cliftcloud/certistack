#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
"""Regenerate THIRD-PARTY-NOTICES.md from the modules the CLI is built with.

Run from the repository root after changing go.mod (Dependabot bumps included):

    python3 scripts/gen-third-party-notices.py

It lists every module compiled into ./cmd/... for Linux, Windows and macOS, with
the license files that module ships. A module it does not know the license
identifier of stops it: classify the new module below after reading its license.
The Go build cache must hold the modules (run `go mod download` first).
"""
import os
import subprocess
import sys

# SPDX expression of each third-party module, from the license files it ships.
LICENSES = {
    "github.com/google/uuid": "BSD-3-Clause",
    "github.com/gowebpki/jcs": "Apache-2.0",
    "github.com/inconshreveable/mousetrap": "Apache-2.0",
    "github.com/klauspost/compress": "BSD-3-Clause AND Apache-2.0 AND MIT",
    "github.com/spf13/cobra": "Apache-2.0",
    "github.com/spf13/pflag": "BSD-3-Clause",
    "golang.org/x/crypto": "BSD-3-Clause",
    "golang.org/x/sys": "BSD-3-Clause",
    "gopkg.in/yaml.v3": "MIT AND Apache-2.0",
}
NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS")


def modules():
    found = {}
    env = dict(os.environ, GOFLAGS="-buildvcs=false")
    for goos in ("linux", "windows", "darwin"):
        out = subprocess.run(
            ["go", "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}", "./cmd/..."],
            env=dict(env, GOOS=goos), capture_output=True, text=True, check=True,
        ).stdout
        for line in out.splitlines():
            path, version, directory = line.split(" ", 2)
            found[path] = (version, directory)
    return dict(sorted(found.items()))


def main():
    mods = modules()
    unknown = [m for m in mods if m not in LICENSES]
    if unknown:
        sys.exit("classify these modules in scripts/gen-third-party-notices.py: " + ", ".join(unknown))
    lines = [
        "# Third-party notices",
        "",
        "CertiStack Community Edition is licensed under the GNU Affero General Public License,",
        "version 3 or later (see `LICENSE`). Its command-line program is built with the",
        "third-party Go modules below, each under its own license, compatible with the AGPL.",
        "Their copyright notices and license texts follow, as those licenses require of a",
        "distribution of the compiled program.",
        "",
        "This file is generated from `go.mod` by `scripts/gen-third-party-notices.py`; a test",
        "(`internal/repocontract`) fails when a module or version in `go.mod` is missing here.",
        "",
        "| Module | Version | License |",
        "|---|---|---|",
    ]
    for path, (version, _) in mods.items():
        lines.append(f"| `{path}` | {version} | {LICENSES[path]} |")
    for path, (version, directory) in mods.items():
        lines += ["", f"## {path} {version}", "", f"License: {LICENSES[path]}", ""]
        files = sorted(f for f in os.listdir(directory) if f.upper().startswith(NAMES) and os.path.isfile(os.path.join(directory, f)))
        if not files:
            sys.exit(f"{path} ships no license file")
        for name in files:
            text = open(os.path.join(directory, name), encoding="utf-8", errors="replace").read().strip("\n")
            lines += [f"### {name}", "", "```text", text, "```", ""]
    open("THIRD-PARTY-NOTICES.md", "w", encoding="utf-8", newline="\n").write("\n".join(lines).rstrip("\n") + "\n")
    print("wrote THIRD-PARTY-NOTICES.md:", ", ".join(f"{p} {v}" for p, (v, _) in mods.items()))


main()
