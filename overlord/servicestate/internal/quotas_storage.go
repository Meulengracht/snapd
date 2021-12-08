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

package internal

import (
	"fmt"
	"os"
	"path/filepath"

	// TODO: move this to snap/quantity? or similar
	"github.com/snapcore/snapd/gadget/quantity"
	"github.com/snapcore/snapd/snap"
)

func sizeOfDirectory(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}

func ensureSnapStorageUsageBelow(storageLimit quantity.Size, snapName string) error {
	// Get installed snap by name
	//commonDir := snap.CommonDataDir(snapName)
	baseDir := snap.BaseDataDir(snapName)

	sizeOfBaseDir, err := sizeOfDirectory(baseDir)
	if err != nil {
		return err
	}

	if quantity.Size(sizeOfBaseDir) > storageLimit {
		return fmt.Errorf("snap %q has disk usage %v, which exceeds the storage limit %v", snapName, sizeOfBaseDir, storageLimit)
	}
	return nil
}

func EnsureSnapListStorageUsageBelow(snaps []string, storageLimit quantity.Size) error {
	// Iterate through all snaps and test their disk usage against the quota
	// group's storage limit. If any snap exceeds the limit, then we cannot
	// decrease the quota
	for _, snapName := range snaps {
		err := ensureSnapStorageUsageBelow(storageLimit, snapName)
		if err != nil {
			return err
		}
	}
	return nil
}

func applyStorageLimitToSnap(snap string, storageLimit quantity.Size) error {
	return nil
}

func ApplyStorageLimitToSnaps(snaps []string, storageLimit quantity.Size) error {
	// Iterate through all snaps and apply the storage limit to them
	for _, snapName := range snaps {
		err := applyStorageLimitToSnap(snapName, storageLimit)
		if err != nil {
			return err
		}
	}
	return nil
}
