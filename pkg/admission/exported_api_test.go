// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import "context"

// Controller.ReadMetrics has no caller in this repository. Enterprise's
// status endpoint calls it, to sample host RAM and I/O wait without evaluating
// admission, so renaming it or changing its signature builds, vets and tests
// clean here and breaks Enterprise. This assignment fails to compile when the
// method or its signature changes; change both repositories together.
var _ func(*Controller, context.Context) (ramPercent, ioWaitPercent float64, err error) = (*Controller).ReadMetrics
