// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package resources

import (
	"fmt"

	"github.com/snapcore/snapd/gadget/quantity"
)

type QuotaResources struct {
	// MemoryLimit is the memory limit for the quota group being controlled,
	// either the initial limit the group is created with for the "create"
	// action, or if non-zero for the "update" the memory limit, then the new
	// value to be set.
	MemoryLimit quantity.Size
}

func (qr *QuotaResources) ValidateLimits() error {
	// make sure the memory limit is not zero
	if qr.MemoryLimit == 0 {
		return fmt.Errorf("cannot create quota group with no memory limit set")
	}

	// make sure the memory limit is at least 4K, that is the minimum size
	// to allow nesting, otherwise groups with less than 4K will trigger the
	// oom killer to be invoked when a new group is added as a sub-group to the
	// larger group.
	if qr.MemoryLimit <= 4*quantity.SizeKiB {
		return fmt.Errorf("memory limit %d is too small: size must be larger than 4KB", qr.MemoryLimit)
	}

	return nil
}
