// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2019 Canonical Ltd
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

package main

import (
	"io"
	"time"

	"github.com/snapcore/secboot"
)

var (
	Parser = parser
)

func MockStdout(newStdout io.Writer) (restore func()) {
	oldStdout := stdout
	stdout = newStdout
	return func() {
		stdout = oldStdout
	}
}

func MockOsutilIsMounted(f func(path string) (bool, error)) (restore func()) {
	oldOsutilIsMounted := osutilIsMounted
	osutilIsMounted = f
	return func() {
		osutilIsMounted = oldOsutilIsMounted
	}
}

func MockTriggerwatchWait(f func(_ time.Duration) error) (restore func()) {
	oldTriggerwatchWait := triggerwatchWait
	triggerwatchWait = f
	return func() {
		triggerwatchWait = oldTriggerwatchWait
	}
}

var DefaultTimeout = defaultTimeout

func MockDefaultMarkerFile(p string) (restore func()) {
	old := defaultMarkerFile
	defaultMarkerFile = p
	return func() {
		defaultMarkerFile = old
	}
}

var (
	UnlockIfEncrypted = unlockIfEncrypted
)

func MockSecbootConnectToDefaultTPM(f func() (*secboot.TPMConnection, error)) (restore func()) {
	old := secbootConnectToDefaultTPM
	secbootConnectToDefaultTPM = f
	return func() {
		secbootConnectToDefaultTPM = old
	}
}

func MockSecbootLockAccessToSealedKeys(f func(tpm *secboot.TPMConnection) error) (restore func()) {
	old := secbootLockAccessToSealedKeys
	secbootLockAccessToSealedKeys = f
	return func() {
		secbootLockAccessToSealedKeys = old
	}
}

func MockSecbootSecureConnectToDefaultTPM(f func(ekCertDataReader io.Reader,
	endorsementAuth []byte) (*secboot.TPMConnection, error)) (restore func()) {
	old := secbootSecureConnectToDefaultTPM
	secbootSecureConnectToDefaultTPM = f
	return func() {
		secbootSecureConnectToDefaultTPM = old
	}
}

func MockSecbootActivateVolumeWithTPMSealedKey(f func(tpm *secboot.TPMConnection, volumeName, sourceDevicePath, keyPath string, pinReader io.Reader, options *secboot.ActivateWithTPMSealedKeyOptions) (bool, error)) (restore func()) {
	old := secbootActivateVolumeWithTPMSealedKey
	secbootActivateVolumeWithTPMSealedKey = f
	return func() {
		secbootActivateVolumeWithTPMSealedKey = old
	}
}

func MockDevDiskByLabelDir(new string) (restore func()) {
	old := devDiskByLabelDir
	devDiskByLabelDir = new
	return func() {
		devDiskByLabelDir = old
	}
}
