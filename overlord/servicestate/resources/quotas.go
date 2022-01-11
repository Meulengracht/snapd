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

// QuotaResourceMemory is the memory limit for the quota group being controlled,
// either the initial limit the group is created with for the "create"
// action, or if non-zero for the "update" the memory limit, then the new
// value to be set.
type QuotaResourceMemory struct {
	MemoryLimit quantity.Size
}

type QuotaResourceCpu struct {
	Count       int
	Percentage  int
	AllowedCpus []int
}

type QuotaResourceThreads struct {
	ThreadLimit int
}

type QuotaResources struct {
	Memory *QuotaResourceMemory
	Cpu    *QuotaResourceCpu
	Thread *QuotaResourceThreads
}

func (qr *QuotaResources) validateMemoryQuota() error {
	// make sure the memory limit is not zero
	if qr.Memory.MemoryLimit == 0 {
		return fmt.Errorf("cannot create quota group with no memory limit set")
	}

	// make sure the memory limit is at least 4K, that is the minimum size
	// to allow nesting, otherwise groups with less than 4K will trigger the
	// oom killer to be invoked when a new group is added as a sub-group to the
	// larger group.
	if qr.Memory.MemoryLimit <= 4*quantity.SizeKiB {
		return fmt.Errorf("memory limit %d is too small: size must be larger than 4KB", qr.Memory.MemoryLimit)
	}
	return nil
}

func (qr *QuotaResources) validateCpuQuota() error {
	// make sure the cpu count is not zero
	if qr.Cpu.Count == 0 && qr.Cpu.Percentage == 0 && len(qr.Cpu.AllowedCpus) == 0 {
		return fmt.Errorf("cannot create quota group with a cpu quota of 0 and allowed cpus of 0")
	}
	return nil
}

func (qr *QuotaResources) validateThreadQuota() error {
	// make sure the thread count is not zero
	if qr.Thread.ThreadLimit == 0 {
		return fmt.Errorf("cannot create quota group with a thread count of 0")
	}
	return nil
}

func (qr *QuotaResources) Validate() error {
	if qr.Memory == nil && qr.Cpu == nil && qr.Thread == nil {
		return fmt.Errorf("quota group must have at least one resource quota set")
	}

	if qr.Memory != nil {
		if err := qr.validateMemoryQuota(); err != nil {
			return err
		}
	}

	if qr.Cpu != nil {
		if err := qr.validateCpuQuota(); err != nil {
			return err
		}
	}

	if qr.Thread != nil {
		if err := qr.validateThreadQuota(); err != nil {
			return err
		}
	}
	return nil
}

func (qr *QuotaResources) ValidateChange(newLimits QuotaResources) error {

	// check that the memory limit is not being decreased
	if newLimits.Memory != nil && newLimits.Memory.MemoryLimit != 0 {
		// we disallow decreasing the memory limit because it is difficult to do
		// so correctly with the current state of our code in
		// EnsureSnapServices, see comment in ensureSnapServicesForGroup for
		// full details
		if qr.Memory != nil && newLimits.Memory.MemoryLimit < qr.Memory.MemoryLimit {
			return fmt.Errorf("cannot decrease memory limit of existing quota-group, remove and re-create it to decrease the limit")
		}
	}

	return nil
}

func (qr *QuotaResources) Change(newLimits QuotaResources) error {
	if err := qr.ValidateChange(newLimits); err != nil {
		return err
	}

	if newLimits.Memory != nil {
		qr.Memory = newLimits.Memory
	}
	if newLimits.Cpu != nil {
		if qr.Cpu == nil {
			qr.Cpu = newLimits.Cpu
		} else {
			// update count/percentage as one unit
			if newLimits.Cpu.Count != 0 || newLimits.Cpu.Percentage != 0 {
				qr.Cpu.Count = newLimits.Cpu.Count
				qr.Cpu.Percentage = newLimits.Cpu.Percentage
			}

			// update allowed cpus as one unit
			if len(newLimits.Cpu.AllowedCpus) != 0 {
				qr.Cpu.AllowedCpus = newLimits.Cpu.AllowedCpus
			}
		}
	}
	if newLimits.Thread != nil {
		qr.Thread = newLimits.Thread
	}
	return nil
}

func CreateQuotaResources(memoryLimit quantity.Size, cpuCount int, cpuPercentage int, allowedCpus []int, threadLimit int) QuotaResources {
	var quotaResources QuotaResources
	if memoryLimit != 0 {
		quotaResources.Memory = &QuotaResourceMemory{
			MemoryLimit: memoryLimit,
		}
	}
	if cpuCount != 0 || cpuPercentage != 0 || len(allowedCpus) != 0 {
		quotaResources.Cpu = &QuotaResourceCpu{
			Count:       cpuCount,
			Percentage:  cpuPercentage,
			AllowedCpus: allowedCpus,
		}
	}
	if threadLimit != 0 {
		quotaResources.Thread = &QuotaResourceThreads{
			ThreadLimit: threadLimit,
		}
	}
	return quotaResources
}
