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

package main_test

import (
	"io/ioutil"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	cmdsnap "github.com/snapcore/snapd/cmd/snap"
	"github.com/snapcore/snapd/image"
	"github.com/snapcore/snapd/snap"
)

type SnapPrepareImageSuite struct {
	BaseSnapSuite
}

var _ = Suite(&SnapPrepareImageSuite{})

func (s *SnapPrepareImageSuite) TestPrepareImageCore(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:  "model",
		PrepareDir: "prepare-dir",
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageClassic(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--classic", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		Classic:    true,
		ModelFile:  "model",
		PrepareDir: "prepare-dir",
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageClassicArch(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--classic", "--arch", "i386", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		Classic:      true,
		Architecture: "i386",
		ModelFile:    "model",
		PrepareDir:   "prepare-dir",
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageClassicWideCohort(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	os.Setenv("UBUNTU_STORE_COHORT_KEY", "is-six-centuries")

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--classic", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		Classic:       true,
		WideCohortKey: "is-six-centuries",
		ModelFile:     "model",
		PrepareDir:    "prepare-dir",
	})

	os.Unsetenv("UBUNTU_STORE_COHORT_KEY")
}

func (s *SnapPrepareImageSuite) TestPrepareImageExtraSnaps(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--channel", "candidate", "--snap", "foo", "--snap", "bar=t/edge", "--snap", "local.snap", "--extra-snaps", "local2.snap", "--extra-snaps", "store-snap"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:    "model",
		Channel:      "candidate",
		PrepareDir:   "prepare-dir",
		Snaps:        []string{"foo", "bar", "local.snap", "local2.snap", "store-snap"},
		SnapChannels: map[string]string{"bar": "t/edge"},
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImageCustomize(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	tmpdir := c.MkDir()
	customizeFile := filepath.Join(tmpdir, "custo.json")
	err := ioutil.WriteFile(customizeFile, []byte(`{
  "console-conf": "disabled",
  "cloud-init-user-data": "cloud-init-user-data"
}`), 0644)
	c.Assert(err, IsNil)

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--customize", customizeFile})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:  "model",
		PrepareDir: "prepare-dir",
		Customizations: image.Customizations{
			ConsoleConf:       "disabled",
			CloudInitUserData: "cloud-init-user-data",
		},
	})
}

func (s *SnapPrepareImageSuite) TestReadSeedManifest(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	var readManifestCalls int
	r = cmdsnap.MockImageReadSeedManifest(func(manifestFile string) (map[string]snap.Revision, error) {
		readManifestCalls++
		c.Check(manifestFile, Equals, "seed.manifest")
		return map[string]snap.Revision{"snapd": {N: 100}}, nil
	})
	defer r()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "model", "prepare-dir", "--revisions", "seed.manifest"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(readManifestCalls, Equals, 1)
	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:  "model",
		PrepareDir: "prepare-dir",
		Revisions:  map[string]snap.Revision{"snapd": {N: 100}},
	})
}

func (s *SnapPrepareImageSuite) TestPrepareImagePreseedArgError(c *C) {
	_, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--preseed-sign-key", "key", "model", "prepare-dir"})
	c.Assert(err, ErrorMatches, `--preseed-sign-key cannot be used without --preseed`)
}

func (s *SnapPrepareImageSuite) TestPrepareImagePreseed(c *C) {
	var opts *image.Options
	prep := func(o *image.Options) error {
		opts = o
		return nil
	}
	r := cmdsnap.MockImagePrepare(prep)
	defer r()

	rest, err := cmdsnap.Parser(cmdsnap.Client()).ParseArgs([]string{"prepare-image", "--preseed", "--preseed-sign-key", "key", "--apparmor-features-dir", "aafeatures-dir", "--sysfs-overlay", "sys-overlay", "model", "prepare-dir"})
	c.Assert(err, IsNil)
	c.Assert(rest, DeepEquals, []string{})

	c.Check(opts, DeepEquals, &image.Options{
		ModelFile:                 "model",
		PrepareDir:                "prepare-dir",
		Preseed:                   true,
		PreseedSignKey:            "key",
		SysfsOverlay:              "sys-overlay",
		AppArmorKernelFeaturesDir: "aafeatures-dir",
	})
}
