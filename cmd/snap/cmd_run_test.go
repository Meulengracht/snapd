// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2024 Canonical Ltd
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/check.v1"

	snaprun "github.com/snapcore/snapd/cmd/snap"
	"github.com/snapcore/snapd/cmd/snaplock/runinhibit"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/features"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/strace"
	"github.com/snapcore/snapd/osutil/user"
	"github.com/snapcore/snapd/sandbox/cgroup"
	"github.com/snapcore/snapd/sandbox/selinux"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/testtime"
	"github.com/snapcore/snapd/testutil"
	"github.com/snapcore/snapd/x11"
)

var mockYaml = []byte(`name: snapname
version: 1.0
apps:
 app:
  command: run-app
 svc:
  command: run-svc
  daemon: simple
hooks:
 configure:
`)

var mockYamlWithComponent = []byte(`name: snapname
version: 1.0
components:
  comp:
    type: standard
    hooks:
      install:
hooks:
 configure:
`)

var mockComponentYaml = []byte(`component: snapname+comp
type: standard
version: 1.0
`)

var mockYamlBaseNone1 = []byte(`name: snapname1
version: 1.0
base: none
apps:
 app:
  command: run-app
`)

var mockYamlBaseNone2 = []byte(`name: snapname2
version: 1.0
base: none
hooks:
 configure:
`)

type RunSuite struct {
	fakeHome string
	BaseSnapSuite
}

var _ = check.Suite(&RunSuite{})

func (s *RunSuite) SetUpTest(c *check.C) {
	s.BaseSnapSuite.SetUpTest(c)
	s.fakeHome = c.MkDir()

	u, err := user.Current()
	c.Assert(err, check.IsNil)
	s.AddCleanup(snaprun.MockUserCurrent(func() (*user.User, error) {
		return &user.User{Uid: u.Uid, HomeDir: s.fakeHome}, nil
	}))
	s.AddCleanup(snaprun.MockCreateTransientScopeForTracking(func(string, *cgroup.TrackingOptions) error {
		return nil
	}))
	s.AddCleanup(snaprun.MockConfirmSystemdAppTracking(func(securityTag string) error {
		// default to showing no existing tracking
		return cgroup.ErrCannotTrackProcess
	}))
	// Mock notices/connections api calls
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/notices":
			c.Assert(r.Method, check.Equals, "POST")
			EncodeResponseBody(c, w, map[string]any{
				"type":   "sync",
				"result": map[string]string{"id": "1"},
			})
		case "/v2/connections":
			EncodeResponseBody(c, w, map[string]any{
				"type":   "sync",
				"result": nil,
			})
		default:
			c.Error("this should never be reached")
		}
	})
}

func (s *RunSuite) TestInvalidParameters(c *check.C) {
	invalidParameters := []string{"run", "--hook=configure", "--command=command-name", "--", "snap-name"}
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs(invalidParameters)
	c.Check(err, check.ErrorMatches, ".*you can only use one of --hook, --command, and --timer.*")

	invalidParameters = []string{"run", "--hook=configure", "--timer=10:00-12:00", "--", "snap-name"}
	_, err = snaprun.Parser(snaprun.Client()).ParseArgs(invalidParameters)
	c.Check(err, check.ErrorMatches, ".*you can only use one of --hook, --command, and --timer.*")

	invalidParameters = []string{"run", "--command=command-name", "--timer=10:00-12:00", "--", "snap-name"}
	_, err = snaprun.Parser(snaprun.Client()).ParseArgs(invalidParameters)
	c.Check(err, check.ErrorMatches, ".*you can only use one of --hook, --command, and --timer.*")

	invalidParameters = []string{"run", "-r=1", "--command=command-name", "--", "snap-name"}
	_, err = snaprun.Parser(snaprun.Client()).ParseArgs(invalidParameters)
	c.Check(err, check.ErrorMatches, ".*-r can only be used with --hook.*")

	invalidParameters = []string{"run", "-r=1", "--", "snap-name"}
	_, err = snaprun.Parser(snaprun.Client()).ParseArgs(invalidParameters)
	c.Check(err, check.ErrorMatches, ".*-r can only be used with --hook.*")

	invalidParameters = []string{"run", "--hook=configure", "--", "foo", "bar", "snap-name"}
	_, err = snaprun.Parser(snaprun.Client()).ParseArgs(invalidParameters)
	c.Check(err, check.ErrorMatches, ".*too many arguments for hook \"configure\": bar.*")
}

func (s *RunSuite) TestRunCmdWithBaseNone(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYamlBaseNone1), &snap.SideInfo{
		Revision: snap.R("1"),
	})
	snaptest.MockSnapCurrent(c, string(mockYamlBaseNone2), &snap.SideInfo{
		Revision: snap.R("1"),
	})

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname1.app", "--arg1", "arg2"})
	c.Assert(err, check.ErrorMatches, `cannot run hooks / applications with base \"none\"`)

	_, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "--", "snapname2"})
	c.Assert(err, check.ErrorMatches, `cannot run hooks / applications with base \"none\"`)
}

func (s *RunSuite) TestSnapRunWhenMissingConfine(c *check.C) {
	_, r := logger.MockLogger()
	defer r()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	var execs [][]string
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execs = append(execs, args)
		return nil
	})
	defer restorer()

	// and run it!
	// a regular run will fail
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.ErrorMatches, `.* your core/snapd package`)
	// a hook run will not fail
	_, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "--", "snapname"})
	c.Assert(err, check.IsNil)

	// but nothing is run ever
	c.Check(execs, check.IsNil)
}

func (s *RunSuite) TestSnapRunAppIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		tmpdir = "/var/tmp"
		os.Setenv("TMPDIR", tmpdir)
		defer os.Unsetenv("TMPDIR")
	}

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
	c.Check(execEnv, testutil.Contains, fmt.Sprintf("TMPDIR=%s", tmpdir))
}

func checkHintFileNotLocked(c *check.C, snapName string) {
	flock, err := openHintFileLock(snapName)
	c.Assert(err, check.IsNil)
	c.Check(flock.TryLock(), check.IsNil)
	flock.Close()
}

func checkHintFileLocked(c *check.C, snapName string) {
	flock, err := openHintFileLock(snapName)
	c.Assert(err, check.IsNil)
	c.Check(flock.TryLock(), check.Equals, osutil.ErrAlreadyLocked)
	flock.Close()
}

func (s *RunSuite) TestSnapRunAppRunsChecksRefreshInhibitionLock(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	var execArg0 string
	var execArgs []string
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		// lock should be released before calling snap-confine using beforeExec() callback
		checkHintFileNotLocked(c, "snapname")

		execArg0 = arg0
		execArgs = args
		return nil
	})
	defer restorer()

	inhibitInfo := runinhibit.InhibitInfo{Previous: snap.R("x2")}
	c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, inhibitInfo, nil), check.IsNil)
	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	var called int
	restore := snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		called++
		c.Check(snapName, check.Equals, "snapname")
		c.Check(ctx, check.NotNil)

		var err error
		flock, err = openHintFileLock(snapName)
		c.Assert(err, check.IsNil)
		// mock held lock and check that it is released after snap run finishes
		c.Assert(flock.ReadLock(), check.IsNil)

		err = notInhibited(ctx)
		c.Assert(err, check.IsNil)

		return flock, nil
	})
	defer restore()

	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1"})
	c.Assert(err, check.IsNil)
	c.Check(called, check.Equals, 1)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1"})

	// lock should be released now
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) testSnapRunAppRunsChecksRemoveInhibitionLock(c *check.C, svc bool) {
	inhibitInfo := runinhibit.InhibitInfo{Previous: snap.R(11)}
	c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRemove, inhibitInfo, nil), check.IsNil)

	cmd := "snapname.app"
	if svc {
		cmd = "snapname.svc"
	}

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", cmd, "--arg1"})
	c.Assert(err, check.ErrorMatches, `cannot run "snapname", snap is being removed`)
}

func (s *RunSuite) TestSnapRunAppRunsChecksRemoveInhibitionLock(c *check.C) {
	const svc = false
	s.testSnapRunAppRunsChecksRemoveInhibitionLock(c, svc)
}

func (s *RunSuite) TestSnapRunAppRunsChecksRemoveInhibitionLockService(c *check.C) {
	const svc = true
	s.testSnapRunAppRunsChecksRemoveInhibitionLock(c, svc)
}

func (s *RunSuite) TestSnapRunAppRefreshAppAwarenessUnsetSkipsInhibitionLockWait(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		return nil
	})
	defer restorer()

	// mark snap as inhibited
	inhibitInfo := runinhibit.InhibitInfo{Previous: snap.R("x2")}
	c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, inhibitInfo, nil), check.IsNil)
	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	// unset refresh-app-awareness flag
	c.Assert(os.RemoveAll(features.RefreshAppAwareness.ControlFile()), check.IsNil)

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1"})
	c.Assert(err, check.ErrorMatches, `cannot run "snapname", snap is being refreshed`)
}

func (s *RunSuite) TestSnapRunAppNewRevisionAfterInhibition(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnap(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	var execEnv []string
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execEnv = envv
		return nil
	})
	defer restorer()

	// mark snap as inhibited
	inhibitInfo := runinhibit.InhibitInfo{Previous: snap.R("x2")}
	c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, inhibitInfo, nil), check.IsNil)
	// unset refresh-app-awareness flag
	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	var called bool
	restore := snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		called = true
		c.Check(snapName, check.Equals, "snapname")

		var err error
		flock, err = openHintFileLock(snapName)
		c.Assert(err, check.IsNil)
		c.Assert(flock.ReadLock(), check.IsNil)

		// snap is inhibited for sometime
		for i := 0; i < 3; i++ {
			cont, err := inhibited(ctx, runinhibit.HintInhibitedForRefresh, &runinhibit.InhibitInfo{Previous: snap.R("x2")})
			c.Assert(err, check.IsNil)
			// non-service apps should keep waiting
			c.Check(cont, check.Equals, false)
		}

		// mock installed snap's new revision with current symlink
		snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x3")})

		// snap is not inhibited anymore
		err = notInhibited(ctx)
		c.Assert(err, check.IsNil)

		return flock, nil
	})
	defer restore()

	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1"})
	c.Assert(err, check.IsNil)
	c.Check(called, check.Equals, true)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1"})
	// Check snap-confine points to latest revision
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x3")

	// lock should be released now
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) TestSnapRunAppMissingAppAfterInhibition(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	const mockYaml1 = `name: snapname
version: 1.0
apps:
 app-1:
  command: run-app
`
	const mockYaml2 = `name: snapname
version: 1.1
apps:
 app-2:
  command: run-app
`

	// mock installed snap
	snaptest.MockSnap(c, string(mockYaml1), &snap.SideInfo{Revision: snap.R("x2")})

	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	var called bool
	restore := snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		called = true
		c.Check(snapName, check.Equals, "snapname")

		// snap is inhibited
		cont, err := inhibited(ctx, runinhibit.HintInhibitedForRefresh, &runinhibit.InhibitInfo{Previous: snap.R("x2")})
		c.Assert(err, check.IsNil)
		// non-service apps should keep waiting
		c.Check(cont, check.Equals, false)

		// mock installed snap's new revision with current symlink
		snaptest.MockSnapCurrent(c, string(mockYaml2), &snap.SideInfo{Revision: snap.R("x3")})

		// snap is not inhibited anymore
		err = notInhibited(ctx)
		c.Assert(err, check.ErrorMatches, `cannot find app "app-1" in "snapname"`)
		return nil, err
	})
	defer restore()

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app-1", "--arg1"})
	c.Assert(err, check.ErrorMatches, `cannot find app "app-1" in "snapname"`)
	c.Check(called, check.Equals, true)
}

func (s *RunSuite) TestSnapRunHookNoRuninhibit(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	restore := snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		return nil, fmt.Errorf("runinhibit.WaitWhileInhibited should not have been called")
	})
	defer restore()

	inhibitInfo := runinhibit.InhibitInfo{Previous: snap.R(42)}
	c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, inhibitInfo, nil), check.IsNil)
	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	// Run a hook from the active revision
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "--", "snapname"})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.hook.configure",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--hook=configure", "snapname"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=42")
}

func (s *RunSuite) TestSnapRunAppRuninhibitSkipsServices(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	var execArg0 string
	var execArgs []string
	var execEnv []string
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	inhibitInfo := runinhibit.InhibitInfo{Previous: snap.R("x2")}
	c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, inhibitInfo, nil), check.IsNil)
	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	var called int
	restore := snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		called++
		c.Check(snapName, check.Equals, "snapname")

		var err error
		flock, err = openHintFileLock(snapName)
		c.Assert(err, check.IsNil)
		c.Assert(flock.ReadLock(), check.IsNil)

		// snap is inhibited
		cont, err := inhibited(ctx, runinhibit.HintInhibitedForRefresh, &inhibitInfo)
		c.Assert(err, check.IsNil)
		// services should not be blocked waiting
		c.Check(cont, check.Equals, true)

		return flock, nil
	})
	defer restore()

	restore = snaprun.MockConfirmSystemdServiceTracking(func(securityTag string) error {
		c.Assert(securityTag, check.Equals, "snap.snapname.svc")
		return nil
	})
	defer restore()

	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.svc"})
	c.Assert(err, check.IsNil)
	c.Check(called, check.Equals, 1)
	c.Assert(rest, check.DeepEquals, []string{"snapname.svc"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"), "snap.snapname.svc",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"), "snapname.svc"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")

	// lock should be released now
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) TestSnapRunAppHintUnlockedOnSnapConfineFailure(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	// mock not-inhibited empty hint
	c.Assert(os.MkdirAll(runinhibit.InhibitDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(runinhibit.HintFile("snapname"), []byte(""), 0644), check.IsNil)

	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	inhibitionFlow := fakeInhibitionFlow{
		start: func(ctx context.Context) error {
			return fmt.Errorf("this should never be reached")
		},
		finish: func(ctx context.Context) error {
			return fmt.Errorf("this should never be reached")
		},
	}
	restore := snaprun.MockInhibitionFlow(&inhibitionFlow)
	defer restore()

	var confirmCgroupCalled int
	restore = snaprun.MockConfirmSystemdAppTracking(func(securityTag string) error {
		confirmCgroupCalled++
		// force error before beforeExec is called
		return fmt.Errorf("boom")
	})
	defer restore()

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1"})
	c.Assert(err, check.ErrorMatches, "boom")
	c.Check(confirmCgroupCalled, check.Equals, 1)

	// lock should be released on failure
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) TestSnapRunAppHintLockedUntilTrackingCgroupIsCreated(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	var execArg0 string
	var execArgs []string
	restore := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		return nil
	})
	defer restore()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	// mock not-inhibited empty hint
	c.Assert(os.MkdirAll(runinhibit.InhibitDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(runinhibit.HintFile("snapname"), []byte(""), 0644), check.IsNil)

	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	inhibitionFlow := fakeInhibitionFlow{
		start: func(ctx context.Context) error {
			return fmt.Errorf("this should never be reached")
		},
		finish: func(ctx context.Context) error {
			return fmt.Errorf("this should never be reached")
		},
	}
	restore = snaprun.MockInhibitionFlow(&inhibitionFlow)
	defer restore()

	var confirmCgroupCalled int
	restore = snaprun.MockConfirmSystemdAppTracking(func(securityTag string) error {
		confirmCgroupCalled++
		// hint file must be locked until transient cgroup is created
		checkHintFileLocked(c, "snapname")
		return nil
	})
	defer restore()

	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1"})
	c.Check(confirmCgroupCalled, check.Equals, 1)

	// lock should be released on failure
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) testSnapRunAppRetryNoInhibitHintFileThenOngoingRefresh(c *check.C, svc bool) {
	logbuf, restore := logger.MockLogger()
	defer restore()

	defer mockSnapConfine(dirs.DistroLibExecDir)()

	var execEnv []string
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execEnv = envv
		return nil
	})
	defer restore()

	// mock installed snap
	si := snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	var startCalled, finishCalled int
	inhibitionFlow := fakeInhibitionFlow{
		start: func(ctx context.Context) error {
			startCalled++
			return nil
		},
		finish: func(ctx context.Context) error {
			finishCalled++
			return nil
		},
	}
	restore = snaprun.MockInhibitionFlow(&inhibitionFlow)
	defer restore()

	var waitWhileInhibitedCalled int
	restore = snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		waitWhileInhibitedCalled++

		c.Check(snapName, check.Equals, "snapname")
		if waitWhileInhibitedCalled == 1 {
			err := notInhibited(ctx)
			c.Assert(err, check.IsNil)

			// mock snap inhibited to trigger race condition detection
			// i.e. we started without a hint lock file (snap on first install)
			// then a refresh started which created the hint lock file.
			c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, runinhibit.InhibitInfo{Previous: snap.R("x2")}, nil), check.IsNil)

			// nil FileLock means no inhibit file exists
			return nil, nil
		} else {
			var err error

			flock, err = openHintFileLock(snapName)
			c.Assert(err, check.IsNil)
			c.Assert(flock.ReadLock(), check.IsNil)

			// snap is inhibited
			cont, err := inhibited(ctx, runinhibit.HintInhibitedForRefresh, &runinhibit.InhibitInfo{Previous: snap.R("x2")})
			c.Check(err, check.IsNil)
			c.Check(cont, check.Equals, false)

			// remove current symlink to add another "current" revision
			c.Assert(os.RemoveAll(filepath.Join(si.MountDir(), "../current")), check.IsNil)
			// update current snap revision
			snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x3")})

			// snap is not inhibited anymore
			err = notInhibited(ctx)
			c.Assert(err, check.IsNil)

			return flock, nil
		}
	})
	defer restore()

	var createCgroupCalled int
	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		createCgroupCalled++
		return nil
	})
	defer restore()

	var confirmCgroupCalled int
	confirmCgroup := func(securityTag string) error {
		confirmCgroupCalled++
		if createCgroupCalled >= 1 || svc {
			// tracking cgroup was already created
			return nil
		}
		// no tracking cgroup exists for current process
		return cgroup.ErrCannotTrackProcess
	}

	if svc {
		restore = snaprun.MockConfirmSystemdServiceTracking(confirmCgroup)
	} else {
		restore = snaprun.MockConfirmSystemdAppTracking(confirmCgroup)
	}
	defer restore()

	cmd := "snapname.app"
	if svc {
		cmd = "snapname.svc"
	}

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--debug-log", "--", cmd})
	c.Assert(err, check.IsNil)

	if svc {
		// no retry, sinlge call
		c.Check(waitWhileInhibitedCalled, check.Equals, 1)
		c.Check(confirmCgroupCalled, check.Equals, 1)
		// service cgroup already created
		c.Check(createCgroupCalled, check.Equals, 0)
		// Check service continued with initial revision
		c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
		// notification flow is not started for services
		c.Check(startCalled, check.Equals, 0)
		c.Check(finishCalled, check.Equals, 0)
		// check no retry logs
		c.Check(strings.Contains(logbuf.String(), "retry due to possible snap refresh conflict detected"), check.Equals, false)
	} else {
		// two calls due to retry
		c.Check(waitWhileInhibitedCalled, check.Equals, 2)
		c.Check(confirmCgroupCalled, check.Equals, 2)
		// cgroup must only be created once and reused for further retries
		// to avoid leaking cgroups
		c.Check(createCgroupCalled, check.Equals, 1)
		// Check snap-confine points to latest revision
		c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x3")
		// notification flow started and finished
		c.Check(startCalled, check.Equals, 1)
		c.Check(finishCalled, check.Equals, 1)
		// check retry behavior is logged
		c.Check(logbuf.String(), testutil.Contains, "retry due to possible snap refresh conflict detected")
	}

	// lock should be released now
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) TestSnapRunAppRetryNoInhibitHintFileThenOngoingRefresh(c *check.C) {
	const svc = false
	s.testSnapRunAppRetryNoInhibitHintFileThenOngoingRefresh(c, svc)
}

func (s *RunSuite) TestSnapRunAppRetryNoInhibitHintFileThenOngoingRefreshService(c *check.C) {
	const svc = true
	s.testSnapRunAppRetryNoInhibitHintFileThenOngoingRefresh(c, svc)
}

func (s *RunSuite) testSnapRunAppRetryNoInhibitHintFileThenOngoingRemove(c *check.C, svc bool) {
	_, restore := logger.MockLogger()
	defer restore()

	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	var waitWhileInhibitedCalled int
	restore = snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		waitWhileInhibitedCalled++

		c.Check(snapName, check.Equals, "snapname")
		err := notInhibited(ctx)
		c.Assert(err, check.IsNil)

		// mock snap inhibited to trigger race condition detection
		// i.e. we started without a hint lock file (snap on first install)
		// then a remove started which created the hint lock file.
		c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRemove, runinhibit.InhibitInfo{Previous: snap.R("x2")}, nil), check.IsNil)

		// nil FileLock means no inhibit file exists
		return nil, nil
	})
	defer restore()

	var createCgroupCalled int
	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		createCgroupCalled++
		return nil
	})
	defer restore()

	var confirmCgroupCalled int
	confirmCgroup := func(securityTag string) error {
		confirmCgroupCalled++
		if createCgroupCalled >= 1 || svc {
			// tracking cgroup was already created
			return nil
		}
		// no tracking cgroup exists for current process
		return cgroup.ErrCannotTrackProcess
	}

	if svc {
		restore = snaprun.MockConfirmSystemdServiceTracking(confirmCgroup)
	} else {
		restore = snaprun.MockConfirmSystemdAppTracking(confirmCgroup)
	}
	defer restore()

	cmd := "snapname.app"
	if svc {
		cmd = "snapname.svc"
	}

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--debug-log", "--", cmd})
	c.Assert(err, check.ErrorMatches, `cannot run "snapname", snap is being removed`)

	// no retry, sinlge call
	c.Check(waitWhileInhibitedCalled, check.Equals, 1)
	c.Check(confirmCgroupCalled, check.Equals, 1)
	if svc {
		// service cgroup already created
		c.Check(createCgroupCalled, check.Equals, 0)
	} else {
		c.Check(createCgroupCalled, check.Equals, 1)
	}

	// lock should be released
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) TestSnapRunAppRetryNoInhibitHintFileThenOngoingRemove(c *check.C) {
	const svc = false
	s.testSnapRunAppRetryNoInhibitHintFileThenOngoingRemove(c, svc)
}

func (s *RunSuite) TestSnapRunAppRetryNoInhibitHintFileThenOngoingRemoveService(c *check.C) {
	const svc = true
	s.testSnapRunAppRetryNoInhibitHintFileThenOngoingRemove(c, svc)
}

func (s *RunSuite) TestSnapRunAppRetryNoInhibitHintFileThenOngoingRefreshMissingCurrent(c *check.C) {
	logbuf, restore := logger.MockLogger()
	defer restore()

	defer mockSnapConfine(dirs.DistroLibExecDir)()

	var execEnv []string
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execEnv = envv
		return nil
	})
	defer restore()

	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	var startCalled, finishCalled int
	inhibitionFlow := fakeInhibitionFlow{
		start: func(ctx context.Context) error {
			startCalled++
			return nil
		},
		finish: func(ctx context.Context) error {
			finishCalled++
			return nil
		},
	}
	restore = snaprun.MockInhibitionFlow(&inhibitionFlow)
	defer restore()

	// Mock that snap exists
	c.Assert(os.MkdirAll(filepath.Join(dirs.SnapMountDir, "snapname"), 0755), check.IsNil)

	var waitWhileInhibitedCalled int
	restore = snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		waitWhileInhibitedCalled++

		c.Check(snapName, check.Equals, "snapname")
		if waitWhileInhibitedCalled == 1 {
			err := notInhibited(ctx)
			// mock edge case where we started without a hint lock file
			// and we have an ongoing refresh which removed current symlink.
			c.Assert(err, testutil.ErrorIs, snaprun.ErrSnapRefreshConflict)
			// and created the inhibition hint lock file.
			c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, runinhibit.InhibitInfo{Previous: snap.R("x2")}, nil), check.IsNil)
			return nil, err
		} else {
			var err error

			flock, err = openHintFileLock(snapName)
			c.Assert(err, check.IsNil)
			c.Assert(flock.ReadLock(), check.IsNil)

			// snap is inhibited
			inhibitInfo := runinhibit.InhibitInfo{Previous: snap.R("x3")}
			// update current snap revision
			snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x3")})
			cont, err := inhibited(ctx, runinhibit.HintInhibitedForRefresh, &inhibitInfo)
			c.Check(err, check.IsNil)
			c.Check(cont, check.Equals, false)

			// snap is not inhibited anymore
			err = notInhibited(ctx)
			c.Assert(err, check.IsNil)

			return flock, nil
		}
	})
	defer restore()

	var createCgroupCalled int
	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		createCgroupCalled++
		return nil
	})
	defer restore()

	var confirmCgroupCalled int
	confirmCgroup := func(securityTag string) error {
		confirmCgroupCalled++
		if createCgroupCalled >= 1 {
			// tracking cgroup was already created
			return nil
		}
		// no tracking cgroup exists for current process
		return cgroup.ErrCannotTrackProcess
	}

	restore = snaprun.MockConfirmSystemdAppTracking(confirmCgroup)
	defer restore()

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--debug-log", "--", "snapname.app"})
	c.Assert(err, check.IsNil)

	// two calls due to retry
	c.Check(waitWhileInhibitedCalled, check.Equals, 2)
	// We entered snap-confine only once
	c.Check(confirmCgroupCalled, check.Equals, 1)
	c.Check(createCgroupCalled, check.Equals, 1)
	// Check snap-confine points to latest revision
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x3")
	// notification flow started and finished
	c.Check(startCalled, check.Equals, 1)
	c.Check(finishCalled, check.Equals, 1)
	// check retry behavior is logged
	c.Check(logbuf.String(), testutil.Contains, "cannot find current revision for snap snapname")
	c.Check(logbuf.String(), testutil.Contains, "retry due to possible snap refresh conflict detected")

	// lock should be released now
	checkHintFileNotLocked(c, "snapname")
}

func (s *RunSuite) TestSnapRunAppMaxRetry(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{Revision: snap.R("x2")})

	c.Assert(os.MkdirAll(dirs.FeaturesDir, 0755), check.IsNil)
	c.Assert(os.WriteFile(features.RefreshAppAwareness.ControlFile(), []byte(nil), 0644), check.IsNil)

	inhibitionFlow := fakeInhibitionFlow{
		start: func(ctx context.Context) error {
			return fmt.Errorf("this should never be reached")
		},
		finish: func(ctx context.Context) error {
			return fmt.Errorf("this should never be reached")
		},
	}
	restore := snaprun.MockInhibitionFlow(&inhibitionFlow)
	defer restore()

	var called int
	restore = snaprun.MockWaitWhileInhibited(func(ctx context.Context, snapName string, notInhibited func(ctx context.Context) error, inhibited func(ctx context.Context, hint runinhibit.Hint, inhibitInfo *runinhibit.InhibitInfo) (cont bool, err error), interval time.Duration) (flock *osutil.FileLock, retErr error) {
		called++
		c.Check(snapName, check.Equals, "snapname")

		err := notInhibited(ctx)
		c.Assert(err, check.IsNil)

		// mock snap inhibited to trigger race condition detection
		// i.e. we started without a hint lock file (snap on first install)
		// then a refresh started which created the hint lock file.
		c.Assert(runinhibit.LockWithHint("snapname", runinhibit.HintInhibitedForRefresh, runinhibit.InhibitInfo{Previous: snap.R("x2")}, nil), check.IsNil)

		// nil FileLock means no inhibit file exists
		return nil, nil
	})
	defer restore()

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1"})
	c.Assert(err, check.ErrorMatches, "race condition detected, snap-run can only retry once")
	// check we only retried once
	c.Check(called, check.Equals, 2)
}

func (s *RunSuite) TestSnapRunClassicAppIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		tmpdir = "/var/tmp"
		os.Setenv("TMPDIR", tmpdir)
		defer os.Unsetenv("TMPDIR")
	}

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml)+"confinement: classic\n", &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"), "--classic",
		"snap.snapname.app",
		filepath.Join(dirs.DistroLibExecDir, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
	c.Check(execEnv, testutil.Contains, fmt.Sprintf("SNAP_SAVED_TMPDIR=%s", tmpdir))
}

func (s *RunSuite) TestSnapRunClassicAppIntegrationReexecedFromCore(c *check.C) {
	mountedCorePath := filepath.Join(dirs.SnapMountDir, "core/current")
	mountedCoreLibExecPath := filepath.Join(mountedCorePath, dirs.CoreLibExecDir)

	defer mockSnapConfine(mountedCoreLibExecPath)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml)+"confinement: classic\n", &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	restore := snaprun.MockOsReadlink(func(name string) (string, error) {
		// pretend 'snap' is reexeced from 'core'
		return filepath.Join(mountedCorePath, "usr/bin/snap"), nil
	})
	defer restore()

	execArgs := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArgs = args
		return nil
	})
	defer restorer()
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(mountedCoreLibExecPath, "snap-confine"), "--classic",
		"snap.snapname.app",
		filepath.Join(mountedCoreLibExecPath, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
}

func (s *RunSuite) TestSnapRunClassicAppIntegrationReexecedFromSnapd(c *check.C) {
	mountedSnapdPath := filepath.Join(dirs.SnapMountDir, "snapd/current")
	mountedSnapdLibExecPath := filepath.Join(mountedSnapdPath, dirs.CoreLibExecDir)

	defer mockSnapConfine(mountedSnapdLibExecPath)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml)+"confinement: classic\n", &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	restore := snaprun.MockOsReadlink(func(name string) (string, error) {
		// pretend 'snap' is reexeced from 'core'
		return filepath.Join(mountedSnapdPath, "usr/bin/snap"), nil
	})
	defer restore()

	execArgs := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArgs = args
		return nil
	})
	defer restorer()
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(mountedSnapdLibExecPath, "snap-confine"), "--classic",
		"snap.snapname.app",
		filepath.Join(mountedSnapdLibExecPath, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
}

func (s *RunSuite) TestSnapRunAppWithCommandIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--command=my-command", "--", "snapname.app", "arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--command=my-command", "snapname.app", "arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=42")
}

func (s *RunSuite) TestSnapRunCreateDataDirs(c *check.C) {
	for _, t := range []struct {
		snapDir string
		opts    *dirs.SnapDirOptions
	}{
		{snapDir: dirs.UserHomeSnapDir},
		{snapDir: dirs.UserHomeSnapDir, opts: &dirs.SnapDirOptions{}},
		{snapDir: dirs.HiddenSnapDataHomeDir, opts: &dirs.SnapDirOptions{HiddenSnapDataDir: true}},
	} {
		s.testSnapRunCreateDataDirs(c, t.snapDir, t.opts)
		c.Assert(os.RemoveAll(s.fakeHome), check.IsNil)
		s.fakeHome = c.MkDir()
	}
}

func (s *RunSuite) testSnapRunCreateDataDirs(c *check.C, snapDir string, opts *dirs.SnapDirOptions) {
	info, err := snap.InfoFromSnapYaml(mockYaml)
	c.Assert(err, check.IsNil)
	info.SideInfo.Revision = snap.R(42)

	err = snaprun.CreateUserDataDirs(info, opts)
	c.Assert(err, check.IsNil)
	c.Check(osutil.FileExists(filepath.Join(s.fakeHome, snapDir, "snapname/42")), check.Equals, true)
	c.Check(osutil.FileExists(filepath.Join(s.fakeHome, snapDir, "snapname/common")), check.Equals, true)

	// check we don't create the alternative dir
	nonExistentDir := dirs.HiddenSnapDataHomeDir
	if snapDir == dirs.HiddenSnapDataHomeDir {
		nonExistentDir = dirs.UserHomeSnapDir
	}

	c.Check(osutil.FileExists(filepath.Join(s.fakeHome, nonExistentDir)), check.Equals, false)
}

func (s *RunSuite) TestParallelInstanceSnapRunCreateDataDirs(c *check.C) {
	info, err := snap.InfoFromSnapYaml(mockYaml)
	c.Assert(err, check.IsNil)
	info.SideInfo.Revision = snap.R(42)
	info.InstanceKey = "foo"

	err = snaprun.CreateUserDataDirs(info, nil)
	c.Assert(err, check.IsNil)
	c.Check(osutil.FileExists(filepath.Join(s.fakeHome, "/snap/snapname_foo/42")), check.Equals, true)
	c.Check(osutil.FileExists(filepath.Join(s.fakeHome, "/snap/snapname_foo/common")), check.Equals, true)
	// mount point for snap instance mapping has been created
	c.Check(osutil.FileExists(filepath.Join(s.fakeHome, "/snap/snapname")), check.Equals, true)
	// and it's empty inside
	m, err := filepath.Glob(filepath.Join(s.fakeHome, "/snap/snapname/*"))
	c.Assert(err, check.IsNil)
	c.Assert(m, check.HasLen, 0)
}

func (s *RunSuite) TestSnapRunHookIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// Run a hook from the active revision
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "--", "snapname"})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.hook.configure",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--hook=configure", "snapname"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=42")
}

func (s *RunSuite) TestSnapRunComponentHookIntegration(c *check.C) {
	const instanceKey = ""
	s.testSnapRunComponentHookIntegration(c, instanceKey)
}

func (s *RunSuite) TestSnapRunComponentHookFromInstanceIntegration(c *check.C) {
	const instanceKey = "instance"
	s.testSnapRunComponentHookIntegration(c, instanceKey)
}

func (s *RunSuite) testSnapRunComponentHookIntegration(c *check.C, instanceKey string) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	var snapInfo *snap.Info
	if instanceKey == "" {
		snapInfo = snaptest.MockSnapCurrent(c, string(mockYamlWithComponent), &snap.SideInfo{
			Revision: snap.R(42),
		})
	} else {
		snapInfo = snaptest.MockSnapInstanceCurrent(c, "snapname_"+instanceKey, string(mockYamlWithComponent), &snap.SideInfo{
			Revision: snap.R(42),
		})
	}

	snaptest.MockComponentCurrent(c, string(mockComponentYaml), snapInfo, snap.ComponentSideInfo{
		Revision: snap.R(21),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	expectedTarget := "snapname+comp"
	if instanceKey != "" {
		expectedTarget = fmt.Sprintf("snapname_%s+comp", instanceKey)
	}

	// Run a hook from the active revision
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=install", "--", expectedTarget})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		fmt.Sprintf("snap.%s.hook.install", expectedTarget),
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--hook=install",
		expectedTarget,
	})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=42")

	// the mount namespace should make it appear as if the instance name is not
	// there from inside the snap
	c.Check(execEnv, testutil.Contains, "SNAP_COMPONENT=/snap/snapname/components/mnt/comp/21")
	c.Check(execEnv, testutil.Contains, "SNAP_COMPONENT_NAME=snapname+comp")
	c.Check(execEnv, testutil.Contains, "SNAP_COMPONENT_VERSION=1.0")
	c.Check(execEnv, testutil.Contains, "SNAP_COMPONENT_REVISION=21")
}

func (s *RunSuite) TestSnapRunHookUnsetRevisionIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// Specifically pass "unset" which would use the active version.
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "-r=unset", "--", "snapname"})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.hook.configure",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--hook=configure", "snapname"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=42")
}

func (s *RunSuite) TestSnapRunHookSpecificRevisionIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	// Create both revisions 41 and 42
	snaptest.MockSnap(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(41),
	})
	snaptest.MockSnap(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// Run a hook on revision 41
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "-r=41", "--", "snapname"})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.hook.configure",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--hook=configure", "snapname"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=41")
}

func (s *RunSuite) TestSnapRunHookMissingRevisionIntegration(c *check.C) {
	// Only create revision 42
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		return nil
	})
	defer restorer()

	// Attempt to run a hook on revision 41, which doesn't exist
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "-r=41", "--", "snapname"})
	c.Assert(err, check.NotNil)
	c.Check(err, check.ErrorMatches, "cannot find .*")
}

func (s *RunSuite) TestSnapRunHookInvalidRevisionIntegration(c *check.C) {
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=configure", "-r=invalid", "--", "snapname"})
	c.Assert(err, check.NotNil)
	c.Check(err, check.ErrorMatches, "invalid snap revision: \"invalid\"")
}

func (s *RunSuite) TestSnapRunHookMissingHookIntegration(c *check.C) {
	// Only create revision 42
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	called := false
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		called = true
		return nil
	})
	defer restorer()

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=missing-hook", "--", "snapname"})
	c.Assert(err, check.ErrorMatches, `cannot find hook "missing-hook" in "snapname"`)
	c.Check(called, check.Equals, false)
}

func (s *RunSuite) TestSnapRunErorsForUnknownRunArg(c *check.C) {
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--unknown", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.ErrorMatches, "unknown flag `unknown'")
}

func (s *RunSuite) TestSnapRunErorsForMissingApp(c *check.C) {
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--command=shell"})
	c.Assert(err, check.ErrorMatches, "need the application to run as argument")
}

func (s *RunSuite) TestSnapRunErrorForUnavailableApp(c *check.C) {
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "not-there"})
	c.Assert(err, check.ErrorMatches, fmt.Sprintf(`snap "not-there" is not installed`))
}

func (s *RunSuite) TestSnapRunSaneEnvironmentHandling(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execEnv = envv
		return nil
	})
	defer restorer()

	// set a SNAP{,_*} variable in the environment
	os.Setenv("SNAP_NAME", "something-else")
	os.Setenv("SNAP_ARCH", "PDP-7")
	defer os.Unsetenv("SNAP_NAME")
	defer os.Unsetenv("SNAP_ARCH")
	// but unrelated stuff is ok
	os.Setenv("SNAP_THE_WORLD", "YES")
	defer os.Unsetenv("SNAP_THE_WORLD")

	// and ensure those SNAP_ vars get overridden
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=42")
	c.Check(execEnv, check.Not(testutil.Contains), "SNAP_NAME=something-else")
	c.Check(execEnv, check.Not(testutil.Contains), "SNAP_ARCH=PDP-7")
	c.Check(execEnv, testutil.Contains, "SNAP_THE_WORLD=YES")
}

func (s *RunSuite) TestSnapRunSnapdHelperPath(c *check.C) {
	_, r := logger.MockLogger()
	defer r()

	var osReadlinkResult string
	restore := snaprun.MockOsReadlink(func(name string) (string, error) {
		return osReadlinkResult, nil
	})
	defer restore()

	tool := "snap-confine"
	for _, t := range []struct {
		readlink string
		expected string
	}{
		{
			filepath.Join(dirs.SnapMountDir, "core/current/usr/bin/snap"),
			filepath.Join(dirs.SnapMountDir, "core/current", dirs.CoreLibExecDir, tool),
		},
		{
			filepath.Join(dirs.SnapMountDir, "snapd/current/usr/bin/snap"),
			filepath.Join(dirs.SnapMountDir, "snapd/current", dirs.CoreLibExecDir, tool),
		},
		{
			filepath.Join("/usr/bin/snap"),
			filepath.Join(dirs.DistroLibExecDir, tool),
		},
		{
			filepath.Join("/home/foo/ws/snapd/snap"),
			filepath.Join(dirs.DistroLibExecDir, tool),
		},
		// unexpected case
		{
			filepath.Join(dirs.SnapMountDir, "snapd2/current/bin/snap"),
			filepath.Join(dirs.DistroLibExecDir, tool),
		},
	} {
		osReadlinkResult = t.readlink
		toolPath, err := snaprun.SnapdHelperPath(tool)
		c.Assert(err, check.IsNil)
		c.Check(toolPath, check.Equals, t.expected)
	}
}

func (s *RunSuite) TestSnapRunAppIntegrationFromCore(c *check.C) {
	defer mockSnapConfine(filepath.Join(dirs.SnapMountDir, "core", "111", dirs.CoreLibExecDir))()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend to be running from core
	restorer := snaprun.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "core/111/usr/bin/snap"), nil
	})
	defer restorer()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
}

func (s *RunSuite) TestSnapRunAppIntegrationFromSnapd(c *check.C) {
	defer mockSnapConfine(filepath.Join(dirs.SnapMountDir, "snapd", "222", dirs.CoreLibExecDir))()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend to be running from snapd
	restorer := snaprun.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "snapd/222/usr/bin/snap"), nil
	})
	defer restorer()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.SnapMountDir, "/snapd/222", dirs.CoreLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.SnapMountDir, "/snapd/222", dirs.CoreLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
}

func (s *RunSuite) TestSnapRunExposeKerberosTickets(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap; happily this also gives us a directory
	// below /tmp which Kerberos ticket exposal expects.
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// create mock Kerberos ticket
	f, err := os.CreateTemp("/tmp", "krb5cc_")
	c.Assert(err, check.IsNil)
	f.Close()
	krbTicketPath := f.Name()
	defer os.Remove(krbTicketPath)

	defer snaprun.MockGetEnv(func(name string) string {
		if name == "KRB5CCNAME" {
			return "FILE:" + krbTicketPath
		}
		return ""
	})()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app"})

	// Ensure environment has expected KRBCCNAME
	expectedKrbTicketPath := "/var/lib/snapd/hostfs/tmp/krb5cc_"
	result := false
	actualKrbTicketPath := ""
	for _, el := range execEnv {
		if strings.HasPrefix(el, "KRB5CCNAME=FILE:") {
			actualKrbTicketPath = filepath.Clean(strings.TrimPrefix(el, "KRB5CCNAME=FILE:"))
			result = strings.HasPrefix(actualKrbTicketPath, expectedKrbTicketPath)
			break
		}
	}
	c.Check(result, check.Equals, true)

	// Now do with again but without any Kerberos set up
	defer snaprun.MockGetEnv(func(name string) string {
		return ""
	})()

	rest, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app"})

	// Ensure environment has gained no KRBCCNAME
	result = true
	for _, el := range execEnv {
		if strings.HasPrefix(el, "KRB5CCNAME=") {
			result = false
			break
		}
	}
	c.Check(result, check.Equals, true)

	// Now do it again but without unsupported Kerberos environment
	logbuf, restore := logger.MockLogger()
	defer restore()
	defer snaprun.MockGetEnv(func(name string) string {
		if name == "KRB5CCNAME" {
			return "FILE:/tmp/unsupported"
		}
		return ""
	})()

	rest, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app"})

	// Ensure environment has gained no KRBCCNAME, because it is unsupported
	result = true
	for _, el := range execEnv {
		if strings.HasPrefix(el, "KRB5CCNAME=") {
			result = false
			break
		}
	}
	c.Check(result, check.Equals, true)
	c.Assert(logbuf.String(), testutil.Contains, "will not expose Kerberos tickets")
}

func (s *RunSuite) TestSnapRunXauthorityMigration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	u, err := user.Current()
	c.Assert(err, check.IsNil)

	// Ensure XDG_RUNTIME_DIR exists for the user we're testing with
	err = os.MkdirAll(filepath.Join(dirs.XdgRuntimeDirBase, u.Uid), 0700)
	c.Assert(err, check.IsNil)

	// mock installed snap; happily this also gives us a directory
	// below /tmp which the Xauthority migration expects.
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	xauthPath, err := x11.MockXauthority(2)
	c.Assert(err, check.IsNil)
	defer os.Remove(xauthPath)

	defer snaprun.MockGetEnv(func(name string) string {
		if name == "XAUTHORITY" {
			return xauthPath
		}
		return ""
	})()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app"})

	expectedXauthPath := filepath.Join(dirs.XdgRuntimeDirBase, u.Uid, ".Xauthority")
	c.Check(execEnv, testutil.Contains, fmt.Sprintf("XAUTHORITY=%s", expectedXauthPath))

	info, err := os.Stat(expectedXauthPath)
	c.Assert(err, check.IsNil)
	c.Assert(info.Mode().Perm(), check.Equals, os.FileMode(0600))

	err = x11.ValidateXauthorityFile(expectedXauthPath)
	c.Assert(err, check.IsNil)
}

// build the args for a hypothetical completer
func mkCompArgs(compPoint string, argv ...string) []string {
	out := []string{
		"99", // COMP_TYPE
		"99", // COMP_KEY
		"",   // COMP_POINT
		"2",  // COMP_CWORD
		" ",  // COMP_WORDBREAKS
	}
	out[2] = compPoint
	out = append(out, strings.Join(argv, " "))
	out = append(out, argv...)
	return out
}

func (s *RunSuite) TestAntialiasHappy(c *check.C) {
	c.Assert(os.MkdirAll(dirs.SnapBinariesDir, 0755), check.IsNil)

	inArgs := mkCompArgs("10", "alias", "alias", "bo-alias")

	// first not so happy because no alias symlink
	app, outArgs := snaprun.Antialias("alias", inArgs)
	c.Check(app, check.Equals, "alias")
	c.Check(outArgs, check.DeepEquals, inArgs)

	c.Assert(os.Symlink("an-app", filepath.Join(dirs.SnapBinariesDir, "alias")), check.IsNil)

	// now really happy
	app, outArgs = snaprun.Antialias("alias", inArgs)
	c.Check(app, check.Equals, "an-app")
	c.Check(outArgs, check.DeepEquals, []string{
		"99",                    // COMP_TYPE (no change)
		"99",                    // COMP_KEY (no change)
		"11",                    // COMP_POINT (+1 because "an-app" is one longer than "alias")
		"2",                     // COMP_CWORD (no change)
		" ",                     // COMP_WORDBREAKS (no change)
		"an-app alias bo-alias", // COMP_LINE (argv[0] changed)
		"an-app",                // argv (arv[0] changed)
		"alias",
		"bo-alias",
	})
}

func (s *RunSuite) TestAntialiasBailsIfUnhappy(c *check.C) {
	// alias exists but args are somehow wonky
	c.Assert(os.MkdirAll(dirs.SnapBinariesDir, 0755), check.IsNil)
	c.Assert(os.Symlink("an-app", filepath.Join(dirs.SnapBinariesDir, "alias")), check.IsNil)

	// weird1 has COMP_LINE not start with COMP_WORDS[0], argv[0] equal to COMP_WORDS[0]
	weird1 := mkCompArgs("6", "alias", "")
	weird1[5] = "xxxxx "
	// weird2 has COMP_LINE not start with COMP_WORDS[0], argv[0] equal to the first word in COMP_LINE
	weird2 := mkCompArgs("6", "xxxxx", "")
	weird2[5] = "alias "

	for desc, inArgs := range map[string][]string{
		"nil args":                     nil,
		"too-short args":               {"alias"},
		"COMP_POINT not a number":      mkCompArgs("hello", "alias"),
		"COMP_POINT is inside argv[0]": mkCompArgs("2", "alias", ""),
		"COMP_POINT is outside argv":   mkCompArgs("99", "alias", ""),
		"COMP_WORDS[0] is not argv[0]": mkCompArgs("10", "not-alias", ""),
		"mismatch between argv[0], COMP_LINE and COMP_WORDS, #1": weird1,
		"mismatch between argv[0], COMP_LINE and COMP_WORDS, #2": weird2,
	} {
		// antialias leaves args alone if it's too short
		app, outArgs := snaprun.Antialias("alias", inArgs)
		c.Check(app, check.Equals, "alias", check.Commentf(desc))
		c.Check(outArgs, check.DeepEquals, inArgs, check.Commentf(desc))
	}
}

func (s *RunSuite) TestSnapRunAppWithStraceIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend we have sudo and simulate some useful output that would
	// normally come from strace
	sudoCmd := testutil.MockCommand(c, "sudo", fmt.Sprintf(`
echo "stdout output 1"
>&2 echo 'execve("/path/to/snap-confine")'
>&2 echo "snap-confine/snap-exec strace stuff"
>&2 echo "getuid() = 1000"
>&2 echo 'execve("%s/snapName/x2/bin/foo")'
>&2 echo "interessting strace output"
>&2 echo "and more"
echo "stdout output 2"
`, dirs.SnapMountDir))
	defer sudoCmd.Restore()

	// pretend we have strace
	straceCmd := testutil.MockCommand(c, "strace", "")
	defer straceCmd.Restore()

	user, err := user.Current()
	c.Assert(err, check.IsNil)

	// and run it under strace
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--strace", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(sudoCmd.Calls(), check.DeepEquals, [][]string{
		{
			"sudo", "-E",
			filepath.Join(straceCmd.BinDir(), "strace"),
			"-u", user.Username,
			"-f",
			"-e", strace.ExcludedSyscalls,
			filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
			"snap.snapname.app",
			filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
			"snapname.app", "--arg1", "arg2",
		},
	})
	c.Check(s.Stdout(), check.Equals, "stdout output 1\nstdout output 2\n")
	c.Check(s.Stderr(), check.Equals, fmt.Sprintf("execve(%q)\ninteressting strace output\nand more\n", filepath.Join(dirs.SnapMountDir, "snapName/x2/bin/foo")))

	s.ResetStdStreams()
	sudoCmd.ForgetCalls()

	// try again without filtering
	rest, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--strace=--raw", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(sudoCmd.Calls(), check.DeepEquals, [][]string{
		{
			"sudo", "-E",
			filepath.Join(straceCmd.BinDir(), "strace"),
			"-u", user.Username,
			"-f",
			"-e", strace.ExcludedSyscalls,
			filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
			"snap.snapname.app",
			filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
			"snapname.app", "--arg1", "arg2",
		},
	})
	c.Check(s.Stdout(), check.Equals, "stdout output 1\nstdout output 2\n")
	expectedFullFmt := `execve("/path/to/snap-confine")
snap-confine/snap-exec strace stuff
getuid() = 1000
execve("%s/snapName/x2/bin/foo")
interessting strace output
and more
`
	expectedFull := fmt.Sprintf(expectedFullFmt, dirs.SnapMountDir)

	for _, tc := range []struct {
		arg   string
		entry []string
	}{
		{arg: "--raw"},
		{arg: "-o foo", entry: []string{"-o", "foo"}},
		{arg: "-o=foo", entry: []string{"-o=foo"}},
		{arg: "--output foo", entry: []string{"--output", "foo"}},
		{arg: "--output=foo", entry: []string{"--output=foo"}},
	} {
		s.ResetStdStreams()
		sudoCmd.ForgetCalls()

		rest, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{
			"run", "--strace=" + tc.arg, "--", "snapname.app", "--arg1", "arg2",
		})
		c.Assert(err, check.IsNil)
		c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
		c.Check(sudoCmd.Calls(), check.DeepEquals, [][]string{
			append(append([]string{
				"sudo", "-E",
				filepath.Join(straceCmd.BinDir(), "strace"),
				"-u", user.Username,
				"-f",
				"-e", strace.ExcludedSyscalls,
			},
				tc.entry...),
				[]string{
					filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
					"snap.snapname.app",
					filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
					"snapname.app", "--arg1", "arg2",
				}...),
		})
		c.Check(s.Stdout(), check.Equals, "stdout output 1\nstdout output 2\n")
		c.Check(s.Stderr(), check.Equals, expectedFull)
	}
	c.Check(s.Stderr(), check.Equals, fmt.Sprintf(expectedFullFmt, dirs.SnapMountDir))
}

func (s *RunSuite) TestSnapRunAppWithStraceOptions(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend we have sudo
	sudoCmd := testutil.MockCommand(c, "sudo", "")
	defer sudoCmd.Restore()

	// pretend we have strace
	straceCmd := testutil.MockCommand(c, "strace", "")
	defer straceCmd.Restore()

	user, err := user.Current()
	c.Assert(err, check.IsNil)

	// and run it under strace
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", `--strace=-tt --raw -o "file with spaces"`, "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(sudoCmd.Calls(), check.DeepEquals, [][]string{
		{
			"sudo", "-E",
			filepath.Join(straceCmd.BinDir(), "strace"),
			"-u", user.Username,
			"-f",
			"-e", strace.ExcludedSyscalls,
			"-tt",
			"-o",
			"file with spaces",
			filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
			"snap.snapname.app",
			filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
			"snapname.app", "--arg1", "arg2",
		},
	})
}

func (s *RunSuite) TestSnapRunShellIntegration(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--shell", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--command=shell", "snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
}

func (s *RunSuite) TestSnapRunAppTimer(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execCalled := false
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execCalled = true
		return nil
	})
	defer restorer()

	fakeNow := time.Date(2018, 02, 12, 9, 55, 0, 0, time.Local)
	restorer = snaprun.MockTimeNow(func() time.Time {
		// Monday Feb 12, 9:55
		return fakeNow
	})
	defer restorer()

	// pretend we are outside of timer range
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", `--timer="mon,10:00~12:00,,fri,13:00"`, "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Assert(execCalled, check.Equals, false)

	c.Check(s.Stderr(), check.Equals, fmt.Sprintf(`%s: attempted to run "snapname.app" timer outside of scheduled time "mon,10:00~12:00,,fri,13:00"
`, fakeNow.Format(time.RFC3339)))
	s.ResetStdStreams()

	restorer = snaprun.MockTimeNow(func() time.Time {
		// Monday Feb 12, 10:20
		return time.Date(2018, 02, 12, 10, 20, 0, 0, time.Local)
	})
	defer restorer()

	// and run it under strace
	_, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", `--timer="mon,10:00~12:00,,fri,13:00"`, "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(execCalled, check.Equals, true)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
}

func (s *RunSuite) TestRunCmdWithTraceExecUnhappy(c *check.C) {
	_, r := logger.MockLogger()
	defer r()

	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("1"),
	})

	// pretend we have sudo
	sudoCmd := testutil.MockCommand(c, "sudo", "echo unhappy; exit 12")
	defer sudoCmd.Restore()

	// pretend we have strace
	straceCmd := testutil.MockCommand(c, "strace", "")
	defer straceCmd.Restore()

	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--trace-exec", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.ErrorMatches, "exit status 12")
	c.Assert(rest, check.DeepEquals, []string{"--", "snapname.app", "--arg1", "arg2"})
	c.Check(s.Stdout(), check.Equals, "unhappy\n")
	c.Check(s.Stderr(), check.Equals, "")
}

func (s *RunSuite) TestSnapRunRestoreSecurityContextHappy(c *check.C) {
	logbuf, restorer := logger.MockLogger()
	defer restorer()

	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalled := 0
	restorer = snaprun.MockSyscallExec(func(_ string, args []string, envv []string) error {
		execCalled++
		return nil
	})
	defer restorer()

	verifyCalls := 0
	restoreCalls := 0
	isEnabledCalls := 0
	enabled := false
	verify := true

	snapUserDir := filepath.Join(s.fakeHome, dirs.UserHomeSnapDir)

	restorer = snaprun.MockSELinuxVerifyPathContext(func(what string) (bool, error) {
		c.Check(what, check.Equals, snapUserDir)
		verifyCalls++
		return verify, nil
	})
	defer restorer()

	restorer = snaprun.MockSELinuxRestoreContext(func(what string, mode selinux.RestoreMode) error {
		c.Check(mode, check.Equals, selinux.RestoreMode{Recursive: true})
		c.Check(what, check.Equals, snapUserDir)
		restoreCalls++
		return nil
	})
	defer restorer()

	restorer = snaprun.MockSELinuxIsEnabled(func() (bool, error) {
		isEnabledCalls++
		return enabled, nil
	})
	defer restorer()

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Check(execCalled, check.Equals, 1)
	c.Check(isEnabledCalls, check.Equals, 1)
	c.Check(verifyCalls, check.Equals, 0)
	c.Check(restoreCalls, check.Equals, 0)

	// pretend SELinux is on
	enabled = true

	_, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Check(execCalled, check.Equals, 2)
	c.Check(isEnabledCalls, check.Equals, 2)
	c.Check(verifyCalls, check.Equals, 1)
	c.Check(restoreCalls, check.Equals, 0)

	// pretend the context does not match
	verify = false

	logbuf.Reset()

	_, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Check(execCalled, check.Equals, 3)
	c.Check(isEnabledCalls, check.Equals, 3)
	c.Check(verifyCalls, check.Equals, 2)
	c.Check(restoreCalls, check.Equals, 1)

	// and we let the user know what we're doing
	c.Check(logbuf.String(), testutil.Contains, fmt.Sprintf("restoring default SELinux context of %s", snapUserDir))
}

func (s *RunSuite) TestSnapRunRestoreSecurityContextFail(c *check.C) {
	logbuf, restorer := logger.MockLogger()
	defer restorer()

	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalled := 0
	restorer = snaprun.MockSyscallExec(func(_ string, args []string, envv []string) error {
		execCalled++
		return nil
	})
	defer restorer()

	verifyCalls := 0
	restoreCalls := 0
	isEnabledCalls := 0
	enabledErr := errors.New("enabled failed")
	verifyErr := errors.New("verify failed")
	restoreErr := errors.New("restore failed")

	snapUserDir := filepath.Join(s.fakeHome, dirs.UserHomeSnapDir)

	restorer = snaprun.MockSELinuxVerifyPathContext(func(what string) (bool, error) {
		c.Check(what, check.Equals, snapUserDir)
		verifyCalls++
		return false, verifyErr
	})
	defer restorer()

	restorer = snaprun.MockSELinuxRestoreContext(func(what string, mode selinux.RestoreMode) error {
		c.Check(mode, check.Equals, selinux.RestoreMode{Recursive: true})
		c.Check(what, check.Equals, snapUserDir)
		restoreCalls++
		return restoreErr
	})
	defer restorer()

	restorer = snaprun.MockSELinuxIsEnabled(func() (bool, error) {
		isEnabledCalls++
		return enabledErr == nil, enabledErr
	})
	defer restorer()

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	// these errors are only logged, but we still run the snap
	c.Assert(err, check.IsNil)
	c.Check(execCalled, check.Equals, 1)
	c.Check(logbuf.String(), testutil.Contains, "cannot determine SELinux status: enabled failed")
	c.Check(isEnabledCalls, check.Equals, 1)
	c.Check(verifyCalls, check.Equals, 0)
	c.Check(restoreCalls, check.Equals, 0)
	// pretend selinux is on
	enabledErr = nil

	logbuf.Reset()

	_, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Check(execCalled, check.Equals, 2)
	c.Check(logbuf.String(), testutil.Contains, fmt.Sprintf("failed to verify SELinux context of %s: verify failed", snapUserDir))
	c.Check(isEnabledCalls, check.Equals, 2)
	c.Check(verifyCalls, check.Equals, 1)
	c.Check(restoreCalls, check.Equals, 0)

	// pretend the context does not match
	verifyErr = nil

	logbuf.Reset()

	_, err = snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Check(execCalled, check.Equals, 3)
	c.Check(logbuf.String(), testutil.Contains, fmt.Sprintf("cannot restore SELinux context of %s: restore failed", snapUserDir))
	c.Check(isEnabledCalls, check.Equals, 3)
	c.Check(verifyCalls, check.Equals, 2)
	c.Check(restoreCalls, check.Equals, 1)
}

// systemctl is-system-running returns "running" in normal situations.
func (s *RunSuite) TestIsStoppingRunning(c *check.C) {
	systemctl := testutil.MockCommand(c, "systemctl", `
case "$1" in
	is-system-running)
		echo "running"
		exit 0
		;;
esac
`)
	defer systemctl.Restore()
	stop, err := snaprun.IsStopping()
	c.Check(err, check.IsNil)
	c.Check(stop, check.Equals, false)
	c.Check(systemctl.Calls(), check.DeepEquals, [][]string{
		{"systemctl", "is-system-running"},
	})
}

// systemctl is-system-running returns "stopping" when the system is
// shutting down or rebooting. At the same time it returns a non-zero
// exit status.
func (s *RunSuite) TestIsStoppingStopping(c *check.C) {
	systemctl := testutil.MockCommand(c, "systemctl", `
case "$1" in
	is-system-running)
		echo "stopping"
		exit 1
		;;
esac
`)
	defer systemctl.Restore()
	stop, err := snaprun.IsStopping()
	c.Check(err, check.IsNil)
	c.Check(stop, check.Equals, true)
	c.Check(systemctl.Calls(), check.DeepEquals, [][]string{
		{"systemctl", "is-system-running"},
	})
}

// systemctl is-system-running can often return "degraded"
// Let's make sure that is not confusing us.
func (s *RunSuite) TestIsStoppingDegraded(c *check.C) {
	systemctl := testutil.MockCommand(c, "systemctl", `
case "$1" in
	is-system-running)
		echo "degraded"
		exit 1
		;;
esac
`)
	defer systemctl.Restore()
	stop, err := snaprun.IsStopping()
	c.Check(err, check.IsNil)
	c.Check(stop, check.Equals, false)
	c.Check(systemctl.Calls(), check.DeepEquals, [][]string{
		{"systemctl", "is-system-running"},
	})
}

func (s *RunSuite) TestSnapRunTrackingApps(c *check.C) {
	restore := mockSnapConfine(filepath.Join(dirs.SnapMountDir, "core", "111", dirs.CoreLibExecDir))
	defer restore()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend to be running from core
	restore = snaprun.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "core/111/usr/bin/snap"), nil
	})
	defer restore()

	created := false
	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		c.Assert(securityTag, check.Equals, "snap.snapname.app")
		c.Assert(opts, check.NotNil)
		c.Assert(opts.AllowSessionBus, check.Equals, true)
		created = true
		return nil
	})
	defer restore()

	restore = snaprun.MockConfirmSystemdServiceTracking(func(securityTag string) error {
		panic("apps need to create a scope and do not use systemd service tracking")
	})
	defer restore()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restore()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
	c.Assert(created, check.Equals, true)
}

func (s *RunSuite) TestSnapRunTrackingHooks(c *check.C) {
	restore := mockSnapConfine(filepath.Join(dirs.SnapMountDir, "core", "111", dirs.CoreLibExecDir))
	defer restore()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend to be running from core
	restore = snaprun.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "core/111/usr/bin/snap"), nil
	})
	defer restore()

	created := false
	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		c.Assert(securityTag, check.Equals, "snap.snapname.hook.configure")
		c.Assert(opts, check.NotNil)
		c.Assert(opts.AllowSessionBus, check.Equals, false)
		created = true
		return nil
	})
	defer restore()

	restore = snaprun.MockConfirmSystemdServiceTracking(func(securityTag string) error {
		panic("hooks need to create a scope and do not use systemd service tracking")
	})
	defer restore()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restore()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook", "configure", "-r", "x2", "snapname"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"),
		"snap.snapname.hook.configure",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--hook=configure", "snapname"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
	c.Assert(created, check.Equals, true)
}

func (s *RunSuite) TestSnapRunTrackingServices(c *check.C) {
	restore := mockSnapConfine(filepath.Join(dirs.SnapMountDir, "core", "111", dirs.CoreLibExecDir))
	defer restore()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend to be running from core
	restore = snaprun.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "core/111/usr/bin/snap"), nil
	})
	defer restore()

	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		panic("services rely on systemd tracking, should not have created a transient scope")
	})
	defer restore()

	confirmed := false
	restore = snaprun.MockConfirmSystemdServiceTracking(func(securityTag string) error {
		confirmed = true
		c.Assert(securityTag, check.Equals, "snap.snapname.svc")
		return nil
	})
	defer restore()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restore()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.svc", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.svc", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"),
		"snap.snapname.svc",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.svc", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
	c.Assert(confirmed, check.Equals, true)
}

func (s *RunSuite) TestSnapRunTrackingServicesWhenRunByUser(c *check.C) {
	restore := mockSnapConfine(filepath.Join(dirs.SnapMountDir, "core", "111", dirs.CoreLibExecDir))
	defer restore()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend to be running from core
	restore = snaprun.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "core/111/usr/bin/snap"), nil
	})
	defer restore()

	var createTransientScopeOpts *cgroup.TrackingOptions
	var createTransientScopeCalls int
	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		createTransientScopeCalls++
		createTransientScopeOpts = opts
		return nil
	})
	defer restore()

	confirmCalls := 0
	restore = snaprun.MockConfirmSystemdServiceTracking(func(securityTag string) error {
		confirmCalls++
		c.Assert(securityTag, check.Equals, "snap.snapname.svc")
		return cgroup.ErrCannotTrackProcess
	})
	defer restore()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restore()

	// invoked as: snap run -- snapname.svc --arg1 arg2
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.svc", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.svc", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"),
		"snap.snapname.svc",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.svc", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
	c.Assert(confirmCalls, check.Equals, 1)
	c.Assert(createTransientScopeCalls, check.Equals, 1)
	c.Assert(createTransientScopeOpts, check.DeepEquals, &cgroup.TrackingOptions{
		AllowSessionBus: true,
	})
}

func (s *RunSuite) TestSnapRunTrackingFailure(c *check.C) {
	restore := mockSnapConfine(filepath.Join(dirs.SnapMountDir, "core", "111", dirs.CoreLibExecDir))
	defer restore()

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// pretend to be running from core
	restore = snaprun.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "core/111/usr/bin/snap"), nil
	})
	defer restore()

	created := false
	restore = snaprun.MockCreateTransientScopeForTracking(func(securityTag string, opts *cgroup.TrackingOptions) error {
		c.Assert(securityTag, check.Equals, "snap.snapname.app")
		c.Assert(opts, check.NotNil)
		c.Assert(opts.AllowSessionBus, check.Equals, true)
		created = true
		// Pretend that the tracking system was unable to track this application.
		return cgroup.ErrCannotTrackProcess
	})
	defer restore()

	restore = snaprun.MockConfirmSystemdServiceTracking(func(securityTag string) error {
		panic("apps need to create a scope and do not use systemd service tracking")
	})
	defer restore()

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restore()

	// Capture the debug log that is printed by this test.
	os.Setenv("SNAPD_DEBUG", "1")
	defer os.Unsetenv("SNAPD_DEBUG")
	logbuf, restore := logger.MockLogger()
	defer restore()

	// and run it!
	rest, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Assert(rest, check.DeepEquals, []string{"snapname.app", "--arg1", "arg2"})
	c.Check(execArg0, check.Equals, filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.SnapMountDir, "/core/111", dirs.CoreLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app", "--arg1", "arg2"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=x2")
	c.Assert(created, check.Equals, true)

	// Ensure that the debug message is printed.
	c.Assert(logbuf.String(), testutil.Contains, "snapd cannot track the started application\n")
}

var mockKernelYaml = []byte(`name: pc-kernel
type: kernel
version: 1.0
hooks:
 fde-setup:
`)

func (s *RunSuite) TestSnapRunHookKernelImplicitBase(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	nModel := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/model":
			switch nModel {
			case 0:
				c.Check(r.Method, check.Equals, "GET")
				c.Check(r.URL.RawQuery, check.Equals, "")
				fmt.Fprint(w, happyUC20ModelAssertionResponse)
			default:
				c.Fatalf("expected to get 1 request for /v2/model, now on %d", nModel+1)
			}
			nModel++
		}
	})

	// mock installed kernel
	snaptest.MockSnapCurrent(c, string(mockKernelYaml), &snap.SideInfo{
		Revision: snap.R(42),
	})

	// redirect exec
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restorer()

	// Run a hook from the active revision
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--hook=fde-setup", "--", "pc-kernel"})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"--base", "core20",
		"snap.pc-kernel.hook.fde-setup",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"--hook=fde-setup", "pc-kernel"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=42")
	c.Check(nModel, check.Equals, 1)
}

func (s *RunSuite) TestRunGdbserverNoGdbserver(c *check.C) {
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", "/no-path:/really-not")
	defer os.Setenv("PATH", oldPath)

	defer mockSnapConfine(dirs.DistroLibExecDir)()
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--gdbserver", "snapname.app"})
	c.Assert(err, check.ErrorMatches, "please install gdbserver on your system")
}

func openHintFileLock(snapName string) (*osutil.FileLock, error) {
	return osutil.NewFileLockWithMode(runinhibit.HintFile(snapName), 0644)
}

func (s *RunSuite) TestCreateSnapDirPermissions(c *check.C) {
	usr, err := user.Current()
	c.Assert(err, check.IsNil)

	usr.HomeDir = s.fakeHome
	snaprun.MockUserCurrent(func() (*user.User, error) {
		return usr, nil
	})

	info := &snap.Info{SuggestedName: "some-snap"}
	c.Assert(snaprun.CreateUserDataDirs(info, nil), check.IsNil)

	fi, err := os.Stat(filepath.Join(s.fakeHome, dirs.UserHomeSnapDir))
	c.Assert(err, check.IsNil)
	c.Assert(fi.Mode()&os.ModePerm, check.Equals, os.FileMode(0700))
}

func (s *RunSuite) TestGetSnapDirOptions(c *check.C) {
	root := c.MkDir()
	dirs.SnapSeqDir = root
	dirs.FeaturesDir = root

	// write sequence file
	seqFile := filepath.Join(dirs.SnapSeqDir, "somesnap.json")
	str := struct {
		MigratedHidden        bool `json:"migrated-hidden"`
		MigratedToExposedHome bool `json:"migrated-exposed-home"`
	}{
		MigratedHidden:        true,
		MigratedToExposedHome: true,
	}
	data, err := json.Marshal(&str)
	c.Assert(err, check.IsNil)
	c.Assert(os.WriteFile(seqFile, data, 0660), check.IsNil)

	// write control file for hidden dir feature
	c.Assert(os.WriteFile(features.HiddenSnapDataHomeDir.ControlFile(), []byte{}, 0660), check.IsNil)

	opts, err := snaprun.GetSnapDirOptions("somesnap")
	c.Assert(err, check.IsNil)
	c.Assert(opts, check.DeepEquals, &dirs.SnapDirOptions{HiddenSnapDataDir: true, MigratedToExposedHome: true})
}

func (s *RunSuite) TestRunDebugLog(c *check.C) {
	oldDebug, isSet := os.LookupEnv("SNAPD_DEBUG")
	if isSet {
		defer os.Setenv("SNAPD_DEBUG", oldDebug)
	} else {
		defer os.Unsetenv("SNAPD_DEBUG")
	}

	logBuf, r := logger.MockLogger()
	defer r()

	restore := mockSnapConfine(dirs.DistroLibExecDir)
	defer restore()
	execArg0 := ""
	execArgs := []string{}
	execEnv := []string{}
	restore = snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execArg0 = arg0
		execArgs = args
		execEnv = envv
		return nil
	})
	defer restore()

	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("12"),
	})

	// this will modify the current process environment
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--debug-log", "snapname.app"})
	c.Assert(err, check.IsNil)
	c.Check(execArg0, check.Equals, filepath.Join(dirs.DistroLibExecDir, "snap-confine"))
	c.Check(execArgs, check.DeepEquals, []string{
		filepath.Join(dirs.DistroLibExecDir, "snap-confine"),
		"snap.snapname.app",
		filepath.Join(dirs.CoreLibExecDir, "snap-exec"),
		"snapname.app"})
	c.Check(execEnv, testutil.Contains, "SNAP_REVISION=12")
	c.Check(execEnv, testutil.Contains, "SNAPD_DEBUG=1")
	// also set in env
	c.Check(os.Getenv("SNAPD_DEBUG"), check.Equals, "1")
	// and we've let the user know that logging was enabled
	c.Check(logBuf.String(), testutil.Contains, "DEBUG: enabled debug logging of early snap startup")
}

func (s *RunSuite) TestSystemKeyMismatchTrivial(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	// system-key on disk
	s.AddCleanup(interfaces.MockSystemKey(`
{
"build-id": "7a94e9736c091b3984bd63f5aebfc883c4d859e0",
"apparmor-features": ["caps", "dbus"]
}`))
	c.Assert(interfaces.WriteSystemKey(interfaces.SystemKeyExtraData{}), check.IsNil)

	// actual snapd system-key we derive is identical

	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		c.Fatalf("unexpected request")
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalls := 0
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execCalls, check.Equals, 1)
	c.Check(n, check.Equals, 0)
}

func (s *RunSuite) mockSystemKeyMismatch(c *check.C) {
	// system-key on disk
	s.AddCleanup(interfaces.MockSystemKey(`
{
"build-id": "7a94e9736c091b3984bd63f5aebfc883c4d859e0",
"apparmor-features": ["caps", "dbus"]
}`))
	c.Assert(interfaces.WriteSystemKey(interfaces.SystemKeyExtraData{}), check.IsNil)

	// actual snapd system-key we derive
	s.AddCleanup(interfaces.MockSystemKey(`
{
"build-id": "7a94e9736c091b3984bd63f5aebfc883c4d859e0",
"apparmor-features": ["caps", "dbus", "more"]
}`))

}

func (s *RunSuite) TestSystemKeyMismatchProceed(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	s.mockSystemKeyMismatch(c)
	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch n {
		case 0:
			c.Check(r.Method, check.Equals, "POST")
			c.Check(r.URL.Path, check.Equals, "/v2/system-info")
			c.Check(r.URL.RawQuery, check.Equals, "")
			fmt.Fprintln(w, `{"type": "sync", "result": null}`)
		default:
			c.Fatalf("expected to get 1 requests, now on %d", n+1)
		}

		n++
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalls := 0
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execCalls, check.Equals, 1)
	c.Check(n, check.Equals, 1)
	c.Check(s.stdout.String(), check.Equals, "")
}

func (s *RunSuite) TestSystemKeyMismatchWaitChange(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	defer snaprun.MockTimeAfter(func(d time.Duration) <-chan time.Time {
		tm := testtime.NewTimer(d)
		defer tm.Elapse(2 * d)
		return tm.ExpiredC()
	})()

	s.mockSystemKeyMismatch(c)

	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch n {
		case 0:
			c.Check(r.Method, check.Equals, "POST")
			c.Check(r.URL.Path, check.Equals, "/v2/system-info")
			c.Check(r.URL.RawQuery, check.Equals, "")
			fmt.Fprintln(w, `{"type": "async", "result": null, "change": "1234"}`)
		case 1:
			c.Check(r.URL.Path, check.Equals, "/v2/changes/1234")
			c.Check(r.Method, check.Equals, "GET")
			fmt.Fprintln(w, `{"type":"sync", "result":{"ready": true, "status": "Done"}}`)
		default:
			c.Fatalf("unexpected request with count %d", n+1)
		}
		n++
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalls := 0
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execCalls, check.Equals, 1)
	c.Check(n, check.Equals, 2)
	c.Check(s.stdout.String(), check.Equals, "")
}

func (s *RunSuite) TestSystemKeyMismatchBackwardCompatUnsupportedAPI(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	s.mockSystemKeyMismatch(c)

	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch n {
		case 0:
			c.Check(r.Method, check.Equals, "POST")
			c.Check(r.URL.Path, check.Equals, "/v2/system-info")
			c.Check(r.URL.RawQuery, check.Equals, "")
			// Method Not Allowed
			w.WriteHeader(405)
			// as if responded by the mux
			fmt.Fprintln(w, `Method not allowed`)
		default:
			c.Fatalf("unexpected request with count %d", n+1)
		}
		n++
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalls := 0
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execCalls, check.Equals, 1)
	c.Check(n, check.Equals, 1)
	c.Check(s.stdout.String(), check.Equals, "")
}

func (s *RunSuite) TestSystemKeyMismatchChangeFails(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	defer snaprun.MockTimeAfter(func(d time.Duration) <-chan time.Time {
		tm := testtime.NewTimer(d)
		defer tm.Elapse(2 * d)
		return tm.ExpiredC()
	})()

	s.mockSystemKeyMismatch(c)

	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch n {
		case 0:
			c.Check(r.Method, check.Equals, "POST")
			c.Check(r.URL.Path, check.Equals, "/v2/system-info")
			c.Check(r.URL.RawQuery, check.Equals, "")
			fmt.Fprintln(w, `{"type": "async", "result": null, "change": "1234"}`)
		case 1:
			c.Check(r.URL.Path, check.Equals, "/v2/changes/1234")
			c.Check(r.Method, check.Equals, "GET")
			// change failed but we continue execution
			fmt.Fprintln(w, `{"type":"sync", "result":{"ready": true, "status": "Error"}}`)
		default:
			c.Fatalf("unexpected request with count %d", n+1)
		}
		n++
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalls := 0
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execCalls, check.Equals, 1)
	c.Check(n, check.Equals, 2)
	c.Check(s.stdout.String(), check.Equals, "")
}

func (s *RunSuite) TestSystemKeyMismatchVersionTooHighNoRestart(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	s.mockSystemKeyMismatch(c)

	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		c.Logf("req %v", n)
		switch n {
		case 0:
			c.Check(r.Method, check.Equals, "POST")
			c.Check(r.URL.Path, check.Equals, "/v2/system-info")
			c.Check(r.URL.RawQuery, check.Equals, "")
			w.WriteHeader(400)
			fmt.Fprintln(w, `{"type": "error", "status-code": "400", "result": {
"message": "system-key version higher than supported",
"kind": "unsupported-system-key-version"
}}`)
		default:
			c.Fatalf("unexpected request with count %d", n+1)
		}
		n++
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalls := 0
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execCalls, check.Equals, 1)
	c.Check(n, check.Equals, 1)
	c.Check(s.stdout.String(), check.Equals, "")
}

func (s *RunSuite) TestSystemKeyMismatchVersionTooHighDaemonRestart(c *check.C) {
	defer mockSnapConfine(dirs.DistroLibExecDir)()

	defer snaprun.MockTimeAfter(func(d time.Duration) <-chan time.Time {
		tm := testtime.NewTimer(d)
		defer tm.Elapse(2 * d)
		return tm.ExpiredC()
	})()

	s.mockSystemKeyMismatch(c)

	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		c.Logf("req %v", n)
		switch n {
		case 0:
			c.Check(r.Method, check.Equals, "POST")
			c.Check(r.URL.Path, check.Equals, "/v2/system-info")
			c.Check(r.URL.RawQuery, check.Equals, "")
			w.WriteHeader(400)
			fmt.Fprintln(w, `
{
  "type": "error", "status-code": "400",
  "result": {
    "message": "system-key version higher than supported",
    "kind": "unsupported-system-key-version"
  },
  "maintenance":{
    "kind": "daemon-restart",
    "message": "snaod is restarting",
    "value": null
  }
}`[1:])
		case 1:
			c.Check(r.Method, check.Equals, "POST")
			c.Check(r.URL.Path, check.Equals, "/v2/system-info")
			c.Check(r.URL.RawQuery, check.Equals, "")
			fmt.Fprintln(w, `{ "type": "sync", "status-code": "200",  "result":  null }`)
		default:
			c.Fatalf("unexpected request with count %d", n+1)
		}
		n++
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	execCalls := 0
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		execCalls++
		return nil
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.IsNil)
	c.Check(execCalls, check.Equals, 1)
	c.Check(n, check.Equals, 2)
	c.Check(s.stdout.String(), check.Equals, "")
}

func (s *RunSuite) TestSystemKeyMismatchRetriesExhausted(c *check.C) {
	defer snaprun.MockGetSystemKeyRetryCount(func() int {
		return 3
	})()

	defer mockSnapConfine(dirs.DistroLibExecDir)()

	defer snaprun.MockTimeAfter(func(d time.Duration) <-chan time.Time {
		tm := testtime.NewTimer(d)
		defer tm.Elapse(2 * d)
		return tm.ExpiredC()
	})()

	s.mockSystemKeyMismatch(c)

	n := 0
	s.RedirectClientToTestServer(func(w http.ResponseWriter, r *http.Request) {
		c.Logf("req %v", n)
		c.Check(r.Method, check.Equals, "POST")
		c.Check(r.URL.Path, check.Equals, "/v2/system-info")
		c.Check(r.URL.RawQuery, check.Equals, "")
		w.WriteHeader(400)
		w.Write(nil)
		n++
	})

	// mock installed snap
	snaptest.MockSnapCurrent(c, string(mockYaml), &snap.SideInfo{
		Revision: snap.R("x2"),
	})

	// redirect exec
	restorer := snaprun.MockSyscallExec(func(arg0 string, args []string, envv []string) error {
		panic("unexpected call")
	})
	defer restorer()

	// and run it!
	_, err := snaprun.Parser(snaprun.Client()).ParseArgs([]string{"run", "--", "snapname.app", "--arg1", "arg2"})
	c.Assert(err, check.ErrorMatches, "timeout waiting for snap system profiles to get updated")
	c.Check(n, check.Equals, 3)
}

func (s *RunSuite) TestDefaultRetryCount(c *check.C) {
	defer os.Unsetenv("SNAPD_DEBUG_SYSTEM_KEY_RETRY")
	c.Check(snaprun.GetSystemKeyRetryCount(), check.Equals, 12)

	os.Setenv("SNAPD_DEBUG_SYSTEM_KEY_RETRY", "123")
	c.Check(snaprun.GetSystemKeyRetryCount(), check.Equals, 123)

	os.Setenv("SNAPD_DEBUG_SYSTEM_KEY_RETRY", "funny")
	// unparsable as int, returns the default value
	c.Check(snaprun.GetSystemKeyRetryCount(), check.Equals, 12)
}
