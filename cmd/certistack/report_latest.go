// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// defaultReportsDir is where run saves its reports unless --output says
// otherwise: <dir>/<plan id>/<report id>.json.
const defaultReportsDir = "/var/lib/certistack/reports"

// newestReport returns the most recently written report under dir, laid out
// as run writes it (<dir>/<plan id>/<report id>.json). It looks only at
// regular files ending in .json in the plan directories one level down; it
// skips hidden names, symbolic links and the directory of refused results.
// Ties in modification time go to the name that sorts last, so the choice
// does not depend on the order the directory is read in.
func newestReport(dir string) (string, error) {
	plans, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("there are no reports in %s yet: run a plan first (certistack run), or name a report file", dir)
	}
	if err != nil {
		return "", fmt.Errorf("cannot list the reports in %s: %w", dir, err)
	}
	var (
		newest     string
		newestTime time.Time
	)
	for _, plan := range plans {
		name := plan.Name()
		if !plan.IsDir() || strings.HasPrefix(name, ".") || name == attest.RefusedDirName {
			continue
		}
		planDir := filepath.Join(dir, name)
		files, err := os.ReadDir(planDir)
		if err != nil {
			return "", fmt.Errorf("cannot list the reports in %s: %w", planDir, err)
		}
		for _, file := range files {
			fileName := file.Name()
			if !file.Type().IsRegular() || strings.HasPrefix(fileName, ".") || !strings.HasSuffix(fileName, ".json") {
				continue
			}
			info, err := file.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return "", fmt.Errorf("cannot read %s: %w", filepath.Join(planDir, fileName), err)
			}
			path := filepath.Join(planDir, fileName)
			if newest == "" || info.ModTime().After(newestTime) || (info.ModTime().Equal(newestTime) && path > newest) {
				newest, newestTime = path, info.ModTime()
			}
		}
	}
	if newest == "" {
		return "", fmt.Errorf("there are no reports in %s yet: run a plan first (certistack run), or name a report file", dir)
	}
	return newest, nil
}
