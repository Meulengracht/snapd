// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020, 2024 Canonical Ltd
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

package boot

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	_ "golang.org/x/crypto/sha3"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/gadget"
	"github.com/snapcore/snapd/gadget/device"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/strutil"
)

type trustedAssetsCache struct {
	cacheDir string
	hash     crypto.Hash
}

func newTrustedAssetsCache(cacheDir string) *trustedAssetsCache {
	return &trustedAssetsCache{cacheDir: cacheDir, hash: crypto.SHA3_384}
}

func (c *trustedAssetsCache) tempAssetRelPath(blName, assetName string) string {
	return filepath.Join(blName, assetName+".temp")
}

func (c *trustedAssetsCache) pathInCache(part string) string {
	return filepath.Join(c.cacheDir, part)
}

func trustedAssetCacheRelPath(blName, assetName, assetHash string) string {
	return filepath.Join(blName, fmt.Sprintf("%s-%s", assetName, assetHash))
}

// fileHash calculates the hash of an arbitrary file using the same hash method
// as the cache.
func (c *trustedAssetsCache) fileHash(name string) (string, error) {
	digest, _, err := osutil.FileDigest(name, c.hash)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

// Add entry for a new named asset owned by a particular bootloader, with the
// binary content of the located at a given path. The cache ensures that only
// one entry for given tuple of (bootloader name, asset name, content-hash)
// exists in the cache.
func (c *trustedAssetsCache) Add(assetPath, blName, assetName string) (*trackedAsset, error) {
	if err := os.MkdirAll(c.pathInCache(blName), 0755); err != nil {
		return nil, fmt.Errorf("cannot create cache directory: %v", err)
	}

	// input
	inf, err := os.Open(assetPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open asset file: %v", err)
	}
	defer inf.Close()
	// temporary output
	tempPath := c.pathInCache(c.tempAssetRelPath(blName, assetName))
	outf, err := osutil.NewAtomicFile(tempPath, 0644, 0, osutil.NoChown, osutil.NoChown)
	if err != nil {
		return nil, fmt.Errorf("cannot create temporary cache file: %v", err)
	}
	defer outf.Cancel()

	// copy and hash at the same time
	h := c.hash.New()
	tr := io.TeeReader(inf, h)
	if _, err := io.Copy(outf, tr); err != nil {
		return nil, fmt.Errorf("cannot copy trusted asset to cache: %v", err)
	}
	hashStr := hex.EncodeToString(h.Sum(nil))
	cacheKey := trustedAssetCacheRelPath(blName, assetName, hashStr)

	ta := &trackedAsset{
		blName: blName,
		name:   assetName,
		hash:   hashStr,
	}

	targetName := c.pathInCache(cacheKey)
	if osutil.FileExists(targetName) {
		// asset is already cached
		return ta, nil
	}
	// commit under a new name
	if err := outf.CommitAs(targetName); err != nil {
		return nil, fmt.Errorf("cannot commit file to assets cache: %v", err)
	}
	return ta, nil
}

func (c *trustedAssetsCache) Remove(blName, assetName, hashStr string) error {
	cacheKey := trustedAssetCacheRelPath(blName, assetName, hashStr)
	if err := os.Remove(c.pathInCache(cacheKey)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// CopyBootAssetsCacheToRoot copies the boot assets cache to a corresponding
// location under a new root directory.
func CopyBootAssetsCacheToRoot(dstRoot string) error {
	if !osutil.IsDirectory(dirs.SnapBootAssetsDir) {
		// nothing to copy
		return nil
	}

	newCacheRoot := dirs.SnapBootAssetsDirUnder(dstRoot)
	if err := os.MkdirAll(newCacheRoot, 0755); err != nil {
		return fmt.Errorf("cannot create cache directory under new root: %v", err)
	}
	err := filepath.Walk(dirs.SnapBootAssetsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(dirs.SnapBootAssetsDir, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := os.MkdirAll(filepath.Join(newCacheRoot, relPath), info.Mode()); err != nil {
				return fmt.Errorf("cannot recreate cache directory %q: %v", relPath, err)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-file entry %q mode %v", relPath, info.Mode())
		}
		if err := osutil.CopyFile(path, filepath.Join(newCacheRoot, relPath), osutil.CopyFlagPreserveAll); err != nil {
			return fmt.Errorf("cannot copy boot asset cache file %q: %v", relPath, err)
		}
		return nil
	})
	return err
}

// ErrObserverNotApplicable indicates that observer is not applicable for use
// with the model.
var ErrObserverNotApplicable = errors.New("observer not applicable")

// TrustedAssetsInstallObserverForModel returns a new trusted assets observer
// for use during installation of the run mode system to track trusted and
// control managed assets, provided the device model indicates this might be
// needed. Otherwise, nil and ErrObserverNotApplicable is returned.
func TrustedAssetsInstallObserverForModel(model *asserts.Model, gadgetDir string, useEncryption bool) (TrustedAssetsInstallObserver, error) {
	if model.Grade() == asserts.ModelGradeUnset {
		// no need to observe updates when assets are not managed
		return nil, ErrObserverNotApplicable
	}
	if gadgetDir == "" {
		return nil, fmt.Errorf("internal error: gadget dir not provided")
	}
	// TODO:UC20: clarify use of empty rootdir when getting the lists of
	// managed and trusted assets
	runBl, runTrusted, runManaged, err := gadgetMaybeTrustedBootloaderAndAssets(gadgetDir, "",
		&bootloader.Options{
			Role:        bootloader.RoleRunMode,
			NoSlashBoot: true,
		})
	if err != nil {
		return nil, err
	}
	// and the recovery bootloader, seed is mounted during install
	seedBl, seedTrusted, _, err := gadgetMaybeTrustedBootloaderAndAssets(gadgetDir, InitramfsUbuntuSeedDir,
		&bootloader.Options{
			Role: bootloader.RoleRecovery,
		})
	if err != nil {
		return nil, err
	}
	_, seedBlHasEfiEntries := seedBl.(bootloader.UefiBootloader)
	if !useEncryption && !seedBlHasEfiEntries {
		// we do not care about trusted assets when not encrypting data
		// partition
		runTrusted = nil
		seedTrusted = nil
	}
	hasManaged := len(runManaged) > 0
	hasTrusted := len(runTrusted) > 0 || len(seedTrusted) > 0
	if !hasManaged && !hasTrusted && !useEncryption {
		// no managed assets, and no trusted assets or we are not
		// tracking them due to no encryption to data partition
		return nil, ErrObserverNotApplicable
	}

	return &trustedAssetsInstallObserverImpl{
		model:     model,
		cache:     newTrustedAssetsCache(dirs.SnapBootAssetsDir),
		gadgetDir: gadgetDir,

		blName:        runBl.Name(),
		managedAssets: runManaged,
		trustedAssets: runTrusted,

		recoveryBlName:        seedBl.Name(),
		trustedRecoveryAssets: seedTrusted,

		seedBootloader: seedBl,
	}, nil
}

type trackedAsset struct {
	blName, name, hash string
}

func isAssetAlreadyTracked(bam bootAssetsMap, newAsset *trackedAsset) bool {
	return isAssetHashTrackedInMap(bam, newAsset.name, newAsset.hash)
}

func isAssetHashTrackedInMap(bam bootAssetsMap, assetName, assetHash string) bool {
	if bam == nil {
		return false
	}
	hashes, ok := bam[assetName]
	if !ok {
		return false
	}
	return strutil.ListContains(hashes, assetHash)
}

// TrustedAssetsInstallObserver tracks the installation of trusted or managed
// boot assets.
type TrustedAssetsInstallObserver interface {
	BootLoaderSupportsEfiVariables() bool
	ObserveExistingTrustedRecoveryAssets(recoveryRootDir string) error
	// FIXME: Combine relevant FDE params into some FDE context that can be
	// passed around instead of passing around many params.
	SetEncryptionParams(key, saveKey secboot.BootstrappedContainer, primaryKey []byte, volumesAuth *device.VolumesAuthOptions)
	UpdateBootEntry() error
	Observe(op gadget.ContentOperation, partRole, root, relativeTarget string, data *gadget.ContentChange) (gadget.ContentChangeAction, error)
}

type trustedAssetsInstallObserverImpl struct {
	model     *asserts.Model
	gadgetDir string
	cache     *trustedAssetsCache

	blName        string
	managedAssets []string
	// trustedAssets records all trusted run asset mapping their
	// relative path to identifier used in the modeenv
	trustedAssets map[string]string
	trackedAssets bootAssetsMap

	recoveryBlName string
	// trustedRecoveryAssets records all trusted recovery asset mapping their
	// relative path to identifier used in the modeenv
	trustedRecoveryAssets map[string]string
	trackedRecoveryAssets bootAssetsMap

	useEncryption             bool
	dataBootstrappedContainer secboot.BootstrappedContainer
	saveBootstrappedContainer secboot.BootstrappedContainer

	seedBootloader bootloader.Bootloader

	primaryKey []byte

	volumesAuth *device.VolumesAuthOptions
}

func (o *trustedAssetsInstallObserverImpl) BootLoaderSupportsEfiVariables() bool {
	_, seedBlHasEfiEntries := o.seedBootloader.(bootloader.UefiBootloader)
	return seedBlHasEfiEntries
}

// Observe observes the operation related to the content of a given gadget
// structure. In particular, the TrustedAssetsInstallObserver tracks writing of
// trusted or managed boot assets, such as the bootloader binary which is
// measured as part of the secure boot or the bootloader configuration.
//
// Implements gadget.ContentObserver.
func (o *trustedAssetsInstallObserverImpl) Observe(op gadget.ContentOperation, partRole, root, relativeTarget string, data *gadget.ContentChange) (gadget.ContentChangeAction, error) {
	if partRole != gadget.SystemBoot {
		// only care about system-boot
		return gadget.ChangeApply, nil
	}

	if len(o.managedAssets) != 0 && strutil.ListContains(o.managedAssets, relativeTarget) {
		// this asset is managed by bootloader installation
		return gadget.ChangeIgnore, nil
	}
	trustedAssetName, isTrustedAsset := o.trustedAssets[relativeTarget]
	if !isTrustedAsset {
		// not one of the trusted assets
		return gadget.ChangeApply, nil
	}
	ta, err := o.cache.Add(data.After, o.blName, trustedAssetName)
	if err != nil {
		return gadget.ChangeAbort, err
	}
	// during installation, modeenv is written out later, at this point we
	// only care that the same file may appear multiple times in gadget
	// structure content, so make sure we are not tracking it yet
	if !isAssetAlreadyTracked(o.trackedAssets, ta) {
		if o.trackedAssets == nil {
			o.trackedAssets = bootAssetsMap{}
		}
		if len(o.trackedAssets[ta.name]) > 0 {
			return gadget.ChangeAbort, fmt.Errorf("cannot reuse asset name %q", ta.name)
		}
		o.trackedAssets[ta.name] = append(o.trackedAssets[ta.name], ta.hash)
	}
	return gadget.ChangeApply, nil
}

// ObserveExistingTrustedRecoveryAssets observes existing trusted assets of a
// recovery bootloader located inside a given root directory.
func (o *trustedAssetsInstallObserverImpl) ObserveExistingTrustedRecoveryAssets(recoveryRootDir string) error {
	if len(o.trustedRecoveryAssets) == 0 {
		// not a trusted assets bootloader or has no trusted assets
		return nil
	}
	for trustedAsset, trustedAssetName := range o.trustedRecoveryAssets {
		path := filepath.Join(recoveryRootDir, trustedAsset)
		if !osutil.FileExists(path) {
			continue
		}
		ta, err := o.cache.Add(path, o.recoveryBlName, trustedAssetName)
		if err != nil {
			return err
		}
		if !isAssetAlreadyTracked(o.trackedRecoveryAssets, ta) {
			if o.trackedRecoveryAssets == nil {
				o.trackedRecoveryAssets = bootAssetsMap{}
			}
			if len(o.trackedRecoveryAssets[ta.name]) > 0 {
				return fmt.Errorf("cannot reuse recovery asset name %q", ta.name)
			}
			o.trackedRecoveryAssets[ta.name] = append(o.trackedRecoveryAssets[ta.name], ta.hash)
		}
	}
	return nil
}

func (o *trustedAssetsInstallObserverImpl) currentTrustedBootAssetsMap() bootAssetsMap {
	return o.trackedAssets
}

func (o *trustedAssetsInstallObserverImpl) currentTrustedRecoveryBootAssetsMap() bootAssetsMap {
	return o.trackedRecoveryAssets
}

func (o *trustedAssetsInstallObserverImpl) SetEncryptionParams(key, saveKey secboot.BootstrappedContainer, primaryKey []byte, volumesAuth *device.VolumesAuthOptions) {
	o.useEncryption = true
	o.dataBootstrappedContainer = key
	o.saveBootstrappedContainer = saveKey
	o.primaryKey = primaryKey
	o.volumesAuth = volumesAuth
}

func (o *trustedAssetsInstallObserverImpl) UpdateBootEntry() error {
	if o.seedBootloader == nil {
		return nil
	}
	efiBl, ok := o.seedBootloader.(bootloader.UefiBootloader)
	if !ok {
		return nil
	}

	var updatedAssets []string
	for name := range o.trackedRecoveryAssets {
		updatedAssets = append(updatedAssets, name)
	}

	return doUpdateBootEntry(efiBl, updatedAssets)
}

// TrustedAssetsUpdateObserverForModel returns a new trusted assets observer for
// tracking changes to the trusted boot assets and preserving managed assets,
// provided the device model indicates this might be needed. Otherwise, nil and
// ErrObserverNotApplicable is returned.
func TrustedAssetsUpdateObserverForModel(model *asserts.Model, gadgetDir string) (*TrustedAssetsUpdateObserver, error) {
	if model.Grade() == asserts.ModelGradeUnset {
		// no need to observe updates when assets are not managed
		return nil, ErrObserverNotApplicable
	}
	// trusted assets need tracking only when the system is using encryption
	// for its data partitions
	trackTrustedAssets := false
	_, err := device.SealedKeysMethod(dirs.GlobalRootDir)
	switch {
	case err == nil:
		trackTrustedAssets = true
	case err == device.ErrNoSealedKeys:
		// nothing to do
	case err != nil:
		// all other errors
		return nil, err
	}

	// see what we need to observe for the run bootloader
	runBl, runTrusted, runManaged, err := gadgetMaybeTrustedBootloaderAndAssets(gadgetDir, InitramfsUbuntuBootDir,
		&bootloader.Options{
			Role:        bootloader.RoleRunMode,
			NoSlashBoot: true,
		})
	if err != nil {
		return nil, err
	}

	// and the recovery bootloader
	seedBl, seedTrusted, seedManaged, err := gadgetMaybeTrustedBootloaderAndAssets(gadgetDir, InitramfsUbuntuSeedDir,
		&bootloader.Options{
			Role: bootloader.RoleRecovery,
		})
	if err != nil {
		return nil, err
	}

	_, seedBlHasEfiEntries := seedBl.(bootloader.UefiBootloader)

	hasManaged := len(runManaged) > 0 || len(seedManaged) > 0
	hasTrusted := len(runTrusted) > 0 || len(seedTrusted) > 0
	if !hasManaged {
		// no managed assets
		if !hasTrusted || (!trackTrustedAssets && !seedBlHasEfiEntries) {
			// no trusted assets or we are not tracking them either
			return nil, ErrObserverNotApplicable
		}
	}

	obs := &TrustedAssetsUpdateObserver{
		cache: newTrustedAssetsCache(dirs.SnapBootAssetsDir),
		model: model,

		bootBootloader:    runBl,
		bootManagedAssets: runManaged,

		seedBootloader:    seedBl,
		seedManagedAssets: seedManaged,
	}
	if trackTrustedAssets || seedBlHasEfiEntries {
		obs.seedTrustedAssets = seedTrusted
		obs.bootTrustedAssets = runTrusted
	}
	return obs, nil
}

// TrustedAssetsUpdateObserver tracks the updates of trusted boot assets and
// attempts to reseal when needed or preserves managed boot assets.
type TrustedAssetsUpdateObserver struct {
	cache *trustedAssetsCache
	model *asserts.Model

	bootBootloader bootloader.Bootloader
	// bootTrustedAssets records all trusted run asset mapping their
	// relative path to identifier used in the modeenv
	bootTrustedAssets map[string]string
	bootManagedAssets []string
	changedAssets     []*trackedAsset

	seedBootloader bootloader.Bootloader
	// seedTrustedAssets records all trusted recovery asset mapping their
	// relative path to identifier used in the modeenv
	seedTrustedAssets map[string]string
	seedManagedAssets []string
	seedChangedAssets []*trackedAsset

	modeenv       *Modeenv
	modeenvLocked bool
}

func doUpdateBootEntry(efiBl bootloader.UefiBootloader, updatedAssets []string) error {
	description, assetPath, optionalData, err := efiBl.ParametersForEfiLoadOption(updatedAssets)
	if err != nil {
		if errors.Is(err, bootloader.ErrNoBootChainFound) {
			logger.Noticef("could not find a valid boot chain, skipping setting EFI variables")
			return nil
		} else {
			return fmt.Errorf("cannot get EFI load option parameter: %v", err)
		}
	}
	if err := SetEfiBootVariables(description, assetPath, optionalData); err != nil {
		return fmt.Errorf("failed to set EFI boot variables: %v", err)
	}
	return nil
}

func (o *TrustedAssetsUpdateObserver) UpdateBootEntry() error {
	efiBl, ok := o.seedBootloader.(bootloader.UefiBootloader)
	if !ok {
		return nil
	}

	var updatedAssets []string
	for _, asset := range o.seedChangedAssets {
		updatedAssets = append(updatedAssets, asset.name)
	}

	return doUpdateBootEntry(efiBl, updatedAssets)
}

// Done must be called when done with the observer if any of the
// gadget.ContenUpdateObserver methods might have been called.
func (o *TrustedAssetsUpdateObserver) Done() {
	if o.modeenvLocked {
		o.modeenvUnlock()
	}
}

func (o *TrustedAssetsUpdateObserver) modeenvUnlock() {
	modeenvUnlock()
	o.modeenvLocked = false
}

func trustedAndManagedAssetsOfBootloader(bl bootloader.Bootloader) (trustedAssets map[string]string, managedAssets []string, revokingAssets []string, err error) {
	tbl, ok := bl.(bootloader.TrustedAssetsBootloader)
	if ok {
		trustedAssets, err = tbl.TrustedAssets()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot list %q bootloader trusted assets: %v", bl.Name(), err)
		}
		managedAssets = tbl.ManagedAssets()
		revokingAssets, err = tbl.RevocationTriggeringAssets()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot list %q bootloader revoking assets: %v", bl.Name(), err)
		}
	}
	return trustedAssets, managedAssets, revokingAssets, nil
}

func findMaybeTrustedBootloaderAndAssets(rootDir string, opts *bootloader.Options) (foundBl bootloader.Bootloader, trustedAssets map[string]string, revokingAssets []string, err error) {
	foundBl, err = bootloader.Find(rootDir, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot find bootloader: %v", err)
	}
	trustedAssets, _, revokingAssets, err = trustedAndManagedAssetsOfBootloader(foundBl)
	return foundBl, trustedAssets, revokingAssets, err
}

func gadgetMaybeTrustedBootloaderAndAssets(gadgetDir, rootDir string, opts *bootloader.Options) (foundBl bootloader.Bootloader, trustedAssets map[string]string, managedAssets []string, err error) {
	foundBl, err = bootloader.ForGadget(gadgetDir, rootDir, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot find bootloader: %v", err)
	}
	trustedAssets, managedAssets, _, err = trustedAndManagedAssetsOfBootloader(foundBl)
	return foundBl, trustedAssets, managedAssets, err
}

// Observe observes the operation related to the update or rollback of the
// content of a given gadget structure. In particular, the
// TrustedAssetsUpdateObserver tracks updates of trusted boot assets such as
// bootloader binaries, or preserves managed assets such as boot configuration.
//
// Implements gadget.ContentUpdateObserver.
func (o *TrustedAssetsUpdateObserver) Observe(op gadget.ContentOperation, partRole, root, relativeTarget string, data *gadget.ContentChange) (gadget.ContentChangeAction, error) {
	var whichBootloader bootloader.Bootloader
	var whichTrustedAssets map[string]string
	var whichManagedAssets []string
	var err error
	var isRecovery bool

	logger.Debugf("observing role %q (root %q, target %q", partRole, root, relativeTarget)
	switch partRole {
	case gadget.SystemBoot:
		whichBootloader = o.bootBootloader
		whichTrustedAssets = o.bootTrustedAssets
		whichManagedAssets = o.bootManagedAssets
	case gadget.SystemSeed, gadget.SystemSeedNull:
		whichBootloader = o.seedBootloader
		whichTrustedAssets = o.seedTrustedAssets
		whichManagedAssets = o.seedManagedAssets
		isRecovery = true
	default:
		// only system-seed and system-boot are of interest
		return gadget.ChangeApply, nil
	}
	// maybe an asset that we manage?
	if len(whichManagedAssets) != 0 && strutil.ListContains(whichManagedAssets, relativeTarget) {
		// this asset is managed directly by the bootloader, preserve it
		if op != gadget.ContentUpdate {
			return gadget.ChangeAbort, fmt.Errorf("internal error: managed bootloader asset change for non update operation %v", op)
		}
		return gadget.ChangeIgnore, nil
	}

	if len(whichTrustedAssets) == 0 {
		// the system is not using encryption for data partitions, so
		// we're done at this point
		return gadget.ChangeApply, nil
	}

	trustedAssetName, hasTrustedAsset := whichTrustedAssets[relativeTarget]
	// maybe an asset that is trusted in the boot process?
	if !hasTrustedAsset {
		// not one of the trusted assets
		return gadget.ChangeApply, nil
	}
	if o.modeenv == nil {
		// we've hit a trusted asset, so a modeenv is needed now too
		modeenvLock()
		o.modeenvLocked = true
		o.modeenv, err = ReadModeenv("")
		if err != nil {
			// for test convenience
			o.modeenvUnlock()
			return gadget.ChangeAbort, fmt.Errorf("cannot load modeenv: %v", err)
		}
	}
	switch op {
	case gadget.ContentUpdate:
		return o.observeUpdate(whichBootloader, isRecovery, trustedAssetName, data)
	case gadget.ContentRollback:
		return o.observeRollback(whichBootloader, isRecovery, root, relativeTarget, trustedAssetName)
	default:
		// we only care about update and rollback actions
		return gadget.ChangeApply, nil
	}
}

func (o *TrustedAssetsUpdateObserver) observeUpdate(bl bootloader.Bootloader, recovery bool, trustedAssetName string, change *gadget.ContentChange) (gadget.ContentChangeAction, error) {
	modeenvBefore, err := o.modeenv.Copy()
	if err != nil {
		return gadget.ChangeAbort, fmt.Errorf("cannot copy modeenv: %v", err)
	}

	// we may be running after a mid-update reboot, where a successful boot
	// would have trimmed the tracked assets hash lists to contain only the
	// asset we booted with

	var taBefore *trackedAsset
	if change.Before != "" {
		// make sure that the original copy is present in the cache if
		// it existed
		taBefore, err = o.cache.Add(change.Before, bl.Name(), trustedAssetName)
		if err != nil {
			return gadget.ChangeAbort, err
		}
	}

	ta, err := o.cache.Add(change.After, bl.Name(), trustedAssetName)
	if err != nil {
		return gadget.ChangeAbort, err
	}

	trustedAssets := &o.modeenv.CurrentTrustedBootAssets
	changedAssets := &o.changedAssets
	if recovery {
		trustedAssets = &o.modeenv.CurrentTrustedRecoveryBootAssets
		changedAssets = &o.seedChangedAssets
	}
	// keep track of the change for cancellation purpose
	*changedAssets = append(*changedAssets, ta)

	if *trustedAssets == nil {
		*trustedAssets = bootAssetsMap{}
	}

	if taBefore != nil && !isAssetAlreadyTracked(*trustedAssets, taBefore) {
		// make sure that the boot asset that was was in the filesystem
		// before the update, is properly tracked until either a
		// successful boot or the update is canceled
		// the original asset hash is listed first
		(*trustedAssets)[taBefore.name] = append([]string{taBefore.hash}, (*trustedAssets)[taBefore.name]...)
	}

	if !isAssetAlreadyTracked(*trustedAssets, ta) {
		if len((*trustedAssets)[ta.name]) > 1 {
			// we expect at most 2 different blobs for a given asset
			// name, the current one and one that will be installed
			// during an update; more entries indicates that the
			// same asset name is used multiple times with different
			// content
			return gadget.ChangeAbort, fmt.Errorf("cannot reuse asset name %q", ta.name)
		}
		// The order of assets is important. Changing it would
		// change assumptions in
		// bootAssetsToLoadChains
		(*trustedAssets)[ta.name] = append((*trustedAssets)[ta.name], ta.hash)
	}

	if o.modeenv.deepEqual(modeenvBefore) {
		return gadget.ChangeApply, nil
	}
	if err := o.modeenv.Write(); err != nil {
		return gadget.ChangeAbort, fmt.Errorf("cannot write modeeenv: %v", err)
	}
	return gadget.ChangeApply, nil
}

func (o *TrustedAssetsUpdateObserver) observeRollback(bl bootloader.Bootloader, recovery bool, root, relativeTarget string, trustedAssetName string) (gadget.ContentChangeAction, error) {
	trustedAssets := &o.modeenv.CurrentTrustedBootAssets
	otherTrustedAssets := o.modeenv.CurrentTrustedRecoveryBootAssets
	if recovery {
		trustedAssets = &o.modeenv.CurrentTrustedRecoveryBootAssets
		otherTrustedAssets = o.modeenv.CurrentTrustedBootAssets
	}

	hashList, ok := (*trustedAssets)[trustedAssetName]
	if !ok || len(hashList) == 0 {
		// asset not tracked in modeenv
		return gadget.ChangeApply, nil
	}

	// new assets are appended to the list
	expectedOldHash := hashList[0]
	// validity check, make sure that the current file is what we expect
	newlyAdded := false
	ondiskHash, err := o.cache.fileHash(filepath.Join(root, relativeTarget))
	if err != nil {
		// file may not exist if it was added by the update, that's ok
		if !os.IsNotExist(err) {
			return gadget.ChangeAbort, fmt.Errorf("cannot calculate the digest of current asset: %v", err)
		}
		newlyAdded = true
		if len(hashList) > 1 {
			// we have more than 1 hash of the asset, so we expected
			// a previous revision to be restored, but got nothing
			// instead
			return gadget.ChangeAbort, fmt.Errorf("tracked asset %q is unexpectedly missing from disk",
				trustedAssetName)
		}
	} else {
		if ondiskHash != expectedOldHash {
			// this is unexpected, a different file exists on disk?
			return gadget.ChangeAbort, fmt.Errorf("unexpected content of existing asset %q", relativeTarget)
		}
	}

	newHash := ""
	if len(hashList) == 1 {
		if newlyAdded {
			newHash = hashList[0]
		}
	} else {
		newHash = hashList[1]
	}
	if newHash != "" && !isAssetHashTrackedInMap(otherTrustedAssets, trustedAssetName, newHash) {
		// asset revision is not used used elsewhere, we can remove it from the cache
		if err := o.cache.Remove(bl.Name(), trustedAssetName, newHash); err != nil {
			// XXX: should this be a log instead?
			return gadget.ChangeAbort, fmt.Errorf("cannot remove unused boot asset %v:%v: %v", trustedAssetName, newHash, err)
		}
	}

	// update modeenv content
	if !newlyAdded {
		(*trustedAssets)[trustedAssetName] = hashList[:1]
	} else {
		delete(*trustedAssets, trustedAssetName)
	}

	if err := o.modeenv.Write(); err != nil {
		return gadget.ChangeAbort, fmt.Errorf("cannot write modeeenv: %v", err)
	}

	return gadget.ChangeApply, nil
}

// BeforeWrite is called when the update process has been staged for execution.
func (o *TrustedAssetsUpdateObserver) BeforeWrite() error {
	if o.modeenv == nil {
		// modeenv wasn't even loaded yet, meaning none of the trusted
		// boot assets was updated
		return nil
	}
	// no model changed => ignore FDE hooks
	opts := ResealKeyToModeenvOptions{ExpectReseal: true, IgnoreFDEHooks: true}
	if err := resealKeyToModeenv(dirs.GlobalRootDir, o.modeenv, opts, nil); err != nil {
		return err
	}
	return nil
}

func (o *TrustedAssetsUpdateObserver) canceledUpdate(recovery bool) {
	trustedAssets := &o.modeenv.CurrentTrustedBootAssets
	otherTrustedAssets := o.modeenv.CurrentTrustedRecoveryBootAssets
	changedAssets := o.changedAssets
	if recovery {
		trustedAssets = &o.modeenv.CurrentTrustedRecoveryBootAssets
		otherTrustedAssets = o.modeenv.CurrentTrustedBootAssets
		changedAssets = o.seedChangedAssets
	}

	if len(*trustedAssets) == 0 {
		return
	}

	for _, changed := range changedAssets {
		hashList, ok := (*trustedAssets)[changed.name]
		if !ok || len(hashList) == 0 {
			// not tracked already, nothing to do
			continue
		}
		if len(hashList) == 1 {
			currentAssetHash := hashList[0]
			if currentAssetHash != changed.hash {
				// assets list has already been trimmed, nothing
				// to do
				continue
			} else {
				// asset was newly added
				delete(*trustedAssets, changed.name)
			}
		} else {
			// asset updates were appended to the list
			(*trustedAssets)[changed.name] = hashList[:1]
		}
		if !isAssetHashTrackedInMap(otherTrustedAssets, changed.name, changed.hash) {
			// asset revision is not used used elsewhere, we can remove it from the cache
			if err := o.cache.Remove(changed.blName, changed.name, changed.hash); err != nil {
				logger.Noticef("cannot remove unused boot asset %v:%v: %v", changed.name, changed.hash, err)
			}
		}
	}
}

// Canceled is called when the update has been canceled, or if changes
// were written and the update has been reverted.
func (o *TrustedAssetsUpdateObserver) Canceled() error {
	if o.modeenv == nil {
		// modeenv wasn't even loaded yet, meaning none of the boot
		// assets was updated
		return nil
	}
	for _, isRecovery := range []bool{false, true} {
		o.canceledUpdate(isRecovery)
	}

	if err := o.modeenv.Write(); err != nil {
		return fmt.Errorf("cannot write modeeenv: %v", err)
	}

	// no model changed => ignore FDE hooks
	opts := ResealKeyToModeenvOptions{ExpectReseal: true, IgnoreFDEHooks: true}
	if err := resealKeyToModeenv(dirs.GlobalRootDir, o.modeenv, opts, nil); err != nil {
		return fmt.Errorf("while canceling gadget update: %v", err)
	}
	return nil
}

func observeSuccessfulBootAssetsForBootloader(m *Modeenv, root string, opts *bootloader.Options) (drop []*trackedAsset, revokeOldKeys bool, err error) {
	trustedAssetsMap := &m.CurrentTrustedBootAssets
	otherTrustedAssetsMap := m.CurrentTrustedRecoveryBootAssets
	whichBootloader := "run mode"
	if opts != nil && opts.Role == bootloader.RoleRecovery {
		trustedAssetsMap = &m.CurrentTrustedRecoveryBootAssets
		otherTrustedAssetsMap = m.CurrentTrustedBootAssets
		whichBootloader = "recovery"
	}

	if len(*trustedAssetsMap) == 0 {
		// bootloader may have trusted assets, but we are not tracking
		// any for the boot process
		return nil, false, nil
	}

	// let's find the bootloader first
	bl, trustedAssets, revokingAssets, err := findMaybeTrustedBootloaderAndAssets(root, opts)
	if err != nil {
		return nil, false, err
	}
	if len(trustedAssets) == 0 {
		// not a trusted assets bootloader, nothing to do
		return nil, false, nil
	}

	cache := newTrustedAssetsCache(dirs.SnapBootAssetsDir)

	alreadySeenAssetNames := make(map[string]bool)
	for trustedAsset, assetName := range trustedAssets {
		_, alreadySeen := alreadySeenAssetNames[assetName]
		if alreadySeen {
			// TrustedAssetsBootloader.TrustedAssets
			// should not map different paths to the same
			// name. If it does it is a bug.
			return nil, false, fmt.Errorf("internal error: bootloader %s has several asset of the same name %s", whichBootloader, assetName)
		}
		assetHash, err := cache.fileHash(filepath.Join(root, trustedAsset))
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, false, fmt.Errorf("cannot calculate the digest of existing trusted asset: %v", err)
			}
			_, inModeenv := (*trustedAssetsMap)[assetName]
			if inModeenv {
				logger.Noticef("system booted without %v bootloader trusted asset %q", whichBootloader, trustedAsset)
				// Asset names are supposed to be unique, that
				// is no 2 different paths can use the same
				// name. If this path is not used, it is safe
				// to say that asset name will not be used
				// either. So we can safely remove it from
				// the trusted asset map.
				delete(*trustedAssetsMap, assetName)
			}
			continue
		}

		// this is what we booted with
		bootedWith := []string{assetHash}
		// one of these was expected during boot
		hashList := (*trustedAssetsMap)[assetName]

		assetFound := false
		// find out if anything needs to be dropped
		for _, hash := range hashList {
			if hash == assetHash {
				assetFound = true
				continue
			}
			if !isAssetHashTrackedInMap(otherTrustedAssetsMap, assetName, hash) {
				// asset can be dropped
				drop = append(drop, &trackedAsset{
					blName: bl.Name(),
					name:   assetName,
					hash:   hash,
				})
			}
		}

		if !assetFound {
			// unexpected, we have booted with an asset whose hash
			// is not listed among the ones we expect

			// TODO:UC20: try to restore the asset from cache
			return nil, false, fmt.Errorf("system booted with unexpected %v bootloader asset %q hash %v", whichBootloader, trustedAsset, assetHash)
		}

		// update the list of what we booted with
		(*trustedAssetsMap)[assetName] = bootedWith

	}

	for _, droppedAsset := range drop {
		for _, revokingAsset := range revokingAssets {
			if revokingAsset == droppedAsset.name {
				// When we drop an old version of shim that means
				// we have updated it. It is likely that the sbatlevel
				// has been updated then. So we should revoke old TPM
				// keys. That will help mitigate attacks resetting the secure boot and
				// reinstalling the older shim and reusing old sealed keys.
				// In the future, we could verify that the shim we dropped
				// had a sbatlevel that is older that the current one.
				revokeOldKeys = true
				break
			}
		}
	}

	return drop, revokeOldKeys, nil
}

// observeSuccessfulBootAssets observes the state of the trusted boot assets
// after a successful boot. Returns a modified modeenv reflecting a new state,
// and a list of assets that can be dropped from the cache.
func observeSuccessfulBootAssets(m *Modeenv) (newM *Modeenv, drop []*trackedAsset, revokeOldKeys bool, err error) {
	// TODO:UC20 only care about run mode for now
	if m.Mode != "run" {
		return m, nil, false, nil
	}

	newM, err = m.Copy()
	if err != nil {
		return nil, nil, false, err
	}

	for _, bl := range []struct {
		root string
		opts *bootloader.Options
	}{
		{
			// ubuntu-boot bootloader
			root: InitramfsUbuntuBootDir,
			opts: &bootloader.Options{Role: bootloader.RoleRunMode, NoSlashBoot: true},
		}, {
			// ubuntu-seed bootloader
			root: InitramfsUbuntuSeedDir,
			opts: &bootloader.Options{Role: bootloader.RoleRecovery, NoSlashBoot: true},
		},
	} {
		dropForBootloader, revoke, err := observeSuccessfulBootAssetsForBootloader(newM, bl.root, bl.opts)
		if err != nil {
			return nil, nil, false, err
		}
		revokeOldKeys = revokeOldKeys || revoke
		drop = append(drop, dropForBootloader...)
	}
	return newM, drop, revokeOldKeys, nil
}
