// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2024 Canonical Ltd
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

package daemon_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/check.v1"

	"github.com/snapcore/snapd/arch"
	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/asserts/snapasserts"
	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/daemon"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/assertstate"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/healthstate"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/snapstate/sequence"
	"github.com/snapcore/snapd/overlord/snapstate/snapstatetest"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/sandbox"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/channel"
	"github.com/snapcore/snapd/snap/naming"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/store"
	"github.com/snapcore/snapd/strutil"
	"github.com/snapcore/snapd/testutil"
)

type snapsSuite struct {
	apiBaseSuite
}

var _ = check.Suite(&snapsSuite{})

func (s *snapsSuite) SetUpTest(c *check.C) {
	s.apiBaseSuite.SetUpTest(c)

	s.expectWriteAccess(daemon.AuthenticatedAccess{Polkit: "io.snapcraft.snapd.manage"})
}

func (s *snapsSuite) expectSnapsReadAccess() {
	s.expectReadAccess(daemon.InterfaceOpenAccess{Interfaces: []string{"snap-refresh-observe", "desktop-launch"}})
}

func (s *snapsSuite) expectSnapsNameReadAccess() {
	s.expectReadAccess(daemon.InterfaceOpenAccess{Interfaces: []string{"snap-interfaces-requests-control", "snap-refresh-observe", "desktop-launch"}})
}

func (s *snapsSuite) TestSnapsInfoIntegration(c *check.C) {
	s.checkSnapsInfoIntegration(c, false, nil)
}

func (s *snapsSuite) TestSnapsInfoIntegrationSome(c *check.C) {
	s.checkSnapsInfoIntegration(c, false, []string{"foo", "baz"})
}

func (s *snapsSuite) TestSnapsInfoIntegrationAll(c *check.C) {
	s.checkSnapsInfoIntegration(c, true, nil)
}

func (s *snapsSuite) TestSnapsInfoIntegrationAllSome(c *check.C) {
	s.checkSnapsInfoIntegration(c, true, []string{"foo", "baz"})
}

func snapList(rawSnaps any) []map[string]any {
	snaps := make([]map[string]any, len(rawSnaps.([]*json.RawMessage)))
	for i, raw := range rawSnaps.([]*json.RawMessage) {
		err := json.Unmarshal([]byte(*raw), &snaps[i])
		if err != nil {
			panic(err)
		}
	}
	return snaps
}

func (s *snapsSuite) checkSnapsInfoIntegration(c *check.C, all bool, names []string) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	type tsnap struct {
		name   string
		dev    string
		ver    string
		rev    int
		active bool

		wanted bool
	}

	tsnaps := []tsnap{
		{name: "foo", dev: "bar", ver: "v0.9", rev: 1},
		{name: "foo", dev: "bar", ver: "v1", rev: 5, active: true},
		{name: "bar", dev: "baz", ver: "v2", rev: 10, active: true},
		{name: "baz", dev: "qux", ver: "v3", rev: 15, active: true},
		{name: "qux", dev: "mip", ver: "v4", rev: 20, active: true},
	}
	numExpected := 0

	for _, snp := range tsnaps {
		if all || snp.active {
			if len(names) == 0 {
				numExpected++
				snp.wanted = true
			}
			for _, n := range names {
				if snp.name == n {
					numExpected++
					snp.wanted = true
					break
				}
			}
		}
		s.mkInstalledInState(c, d, snp.name, snp.dev, snp.ver, snap.R(snp.rev), snp.active, "")
	}

	q := url.Values{}
	if all {
		q.Set("select", "all")
	}
	if len(names) > 0 {
		q.Set("snaps", strings.Join(names, ","))
	}
	req, err := http.NewRequest("GET", "/v2/snaps?"+q.Encode(), nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, check.Equals, 200)
	c.Check(rsp.Result, check.NotNil)

	snaps := snapList(rsp.Result)
	c.Check(snaps, check.HasLen, numExpected)

	for _, s := range tsnaps {
		if !((all || s.active) && s.wanted) {
			continue
		}
		var got map[string]any
		for _, got = range snaps {
			if got["name"].(string) == s.name && got["revision"].(string) == snap.R(s.rev).String() {
				break
			}
		}
		c.Check(got["name"], check.Equals, s.name)
		c.Check(got["version"], check.Equals, s.ver)
		c.Check(got["revision"], check.Equals, snap.R(s.rev).String())
		c.Check(got["developer"], check.Equals, s.dev)
		c.Check(got["confinement"], check.Equals, "strict")
	}
}

func (s *snapsSuite) TestSnapsInfoOnlyLocal(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	s.rsnaps = []*snap.Info{{
		SideInfo: snap.SideInfo{
			RealName: "store",
		},
		Publisher: snap.StoreAccount{
			ID:          "foo-id",
			Username:    "foo",
			DisplayName: "Foo",
			Validation:  "unproven",
		},
	}}
	s.mkInstalledInState(c, d, "local", "foo", "v1", snap.R(10), true, "")
	st := d.Overlord().State()
	st.Lock()
	st.Set("health", map[string]healthstate.HealthState{
		"local": {Status: healthstate.OkayStatus},
	})
	st.Unlock()

	req, err := http.NewRequest("GET", "/v2/snaps?sources=local", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Sources, check.DeepEquals, []string{"local"})

	snaps := snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 1)
	c.Assert(snaps[0]["name"], check.Equals, "local")
	c.Check(snaps[0]["health"], check.DeepEquals, map[string]any{
		"status":    "okay",
		"revision":  "unset",
		"timestamp": "0001-01-01T00:00:00Z",
	})
}

func (s *snapsSuite) TestSnapsInfoAllMixedPublishers(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	// the first 'local' is from a 'local' snap
	s.mkInstalledInState(c, d, "local", "", "v1", snap.R(-1), false, "")
	s.mkInstalledInState(c, d, "local", "foo", "v2", snap.R(1), false, "")
	s.mkInstalledInState(c, d, "local", "foo", "v3", snap.R(2), true, "")

	req, err := http.NewRequest("GET", "/v2/snaps?select=all", nil)
	c.Assert(err, check.IsNil)
	rsp := s.syncReq(c, req, nil, actionIsExpected)

	snaps := snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 3)

	publisher := map[string]any{
		"id":           "foo-id",
		"username":     "foo",
		"display-name": "Foo",
		"validation":   "unproven",
	}

	c.Check(snaps[0]["publisher"], check.IsNil)
	c.Check(snaps[1]["publisher"], check.DeepEquals, publisher)
	c.Check(snaps[2]["publisher"], check.DeepEquals, publisher)
}

func (s *snapsSuite) TestSnapsInfoAll(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	s.mkInstalledInState(c, d, "local", "foo", "v1", snap.R(1), false, "")
	s.mkInstalledInState(c, d, "local", "foo", "v2", snap.R(2), false, "")
	s.mkInstalledInState(c, d, "local", "foo", "v3", snap.R(3), true, "")
	s.mkInstalledInState(c, d, "local_foo", "foo", "v4", snap.R(4), true, "")
	brokenInfo := s.mkInstalledInState(c, d, "local_bar", "foo", "v5", snap.R(5), true, "")
	// make sure local_bar is 'broken'
	err := os.Remove(filepath.Join(brokenInfo.MountDir(), "meta", "snap.yaml"))
	c.Assert(err, check.IsNil)

	expectedHappy := map[string]bool{
		"local":     true,
		"local_foo": true,
		"local_bar": true,
	}
	for _, t := range []struct {
		q        string
		numSnaps int
		typ      daemon.ResponseType
	}{
		{"?select=enabled", 3, "sync"},
		{`?select=`, 3, "sync"},
		{"", 3, "sync"},
		{"?select=all", 5, "sync"},
		{"?select=invalid-field", 0, "error"},
	} {
		c.Logf("trying: %v", t)
		req, err := http.NewRequest("GET", fmt.Sprintf("/v2/snaps%s", t.q), nil)
		c.Assert(err, check.IsNil)
		rsp := s.jsonReq(c, req, nil, actionIsExpected)
		c.Assert(rsp.Type, check.Equals, t.typ)

		if rsp.Type != "error" {
			snaps := snapList(rsp.Result)
			c.Assert(snaps, check.HasLen, t.numSnaps)
			seen := map[string]bool{}
			for _, s := range snaps {
				seen[s["name"].(string)] = true
			}
			c.Assert(seen, check.DeepEquals, expectedHappy)
		}
	}
}

func (s *snapsSuite) TestSnapsInfoOnlyStore(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	s.suggestedCurrency = "EUR"

	s.rsnaps = []*snap.Info{{
		SideInfo: snap.SideInfo{
			RealName: "store",
		},
		Publisher: snap.StoreAccount{
			ID:          "foo-id",
			Username:    "foo",
			DisplayName: "Foo",
			Validation:  "unproven",
		},
	}}
	s.mkInstalledInState(c, d, "local", "foo", "v1", snap.R(10), true, "")

	req, err := http.NewRequest("GET", "/v2/snaps?sources=store", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Sources, check.DeepEquals, []string{"store"})

	snaps := snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 1)
	c.Assert(snaps[0]["name"], check.Equals, "store")
	c.Check(snaps[0]["prices"], check.IsNil)

	c.Check(rsp.SuggestedCurrency, check.Equals, "EUR")
}

func (s *snapsSuite) TestSnapsInfoStoreWithAuth(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	state := d.Overlord().State()
	state.Lock()
	user, err := auth.NewUser(state, auth.NewUserParams{
		Username:   "username",
		Email:      "email@test.com",
		Macaroon:   "macaroon",
		Discharges: []string{"discharge"},
	})
	state.Unlock()
	c.Check(err, check.IsNil)

	req, err := http.NewRequest("GET", "/v2/snaps?sources=store", nil)
	c.Assert(err, check.IsNil)

	c.Assert(s.user, check.IsNil)

	_ = s.syncReq(c, req, user, actionIsExpected)

	// ensure user was set
	c.Assert(s.user, check.DeepEquals, user)
}

func (s *snapsSuite) TestSnapsInfoLocalAndStore(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	s.rsnaps = []*snap.Info{{
		Version: "v42",
		SideInfo: snap.SideInfo{
			RealName: "remote",
		},
		Publisher: snap.StoreAccount{
			ID:          "foo-id",
			Username:    "foo",
			DisplayName: "Foo",
			Validation:  "unproven",
		},
	}}
	s.mkInstalledInState(c, d, "local", "foo", "v1", snap.R(10), true, "")

	req, err := http.NewRequest("GET", "/v2/snaps?sources=local,store", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	// presence of 'store' in sources bounces request over to /find
	c.Assert(rsp.Sources, check.DeepEquals, []string{"store"})

	snaps := snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 1)
	c.Check(snaps[0]["version"], check.Equals, "v42")

	// as does a 'q'
	req, err = http.NewRequest("GET", "/v2/snaps?q=what", nil)
	c.Assert(err, check.IsNil)
	rsp = s.syncReq(c, req, nil, actionIsExpected)
	snaps = snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 1)
	c.Check(snaps[0]["version"], check.Equals, "v42")

	// otherwise, local only
	req, err = http.NewRequest("GET", "/v2/snaps", nil)
	c.Assert(err, check.IsNil)
	rsp = s.syncReq(c, req, nil, actionIsExpected)
	snaps = snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 1)
	c.Check(snaps[0]["version"], check.Equals, "v1")
}

func (s *snapsSuite) TestSnapsInfoDefaultSources(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)

	s.rsnaps = []*snap.Info{{
		SideInfo: snap.SideInfo{
			RealName: "remote",
		},
		Publisher: snap.StoreAccount{
			ID:          "foo-id",
			Username:    "foo",
			DisplayName: "Foo",
			Validation:  "unproven",
		},
	}}
	s.mkInstalledInState(c, d, "local", "foo", "v1", snap.R(10), true, "")

	req, err := http.NewRequest("GET", "/v2/snaps", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Sources, check.DeepEquals, []string{"local"})
	snaps := snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 1)
}

func (s *snapsSuite) TestSnapsInfoFilterRemote(c *check.C) {
	s.expectSnapsReadAccess()
	s.daemon(c)

	s.rsnaps = nil

	req, err := http.NewRequest("GET", "/v2/snaps?q=foo&sources=store", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Check(s.storeSearch, check.DeepEquals, store.Search{Query: "foo"})

	c.Assert(rsp.Result, check.NotNil)
}

func (s *snapsSuite) TestPostSnapsVerifyMultiSnapInstruction(c *check.C) {
	s.daemonWithOverlordMockAndStore()

	buf := strings.NewReader(`{"action": "install","snaps":["ubuntu-core"]}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, testutil.Contains, `cannot install "ubuntu-core", please use "core" instead`)
}

func (s *snapsSuite) TestPostSnapsUnsupportedMultiOp(c *check.C) {
	s.daemonWithOverlordMockAndStore()

	buf := strings.NewReader(`{"action": "switch","snaps":["foo"]}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, testutil.Contains, `unsupported multi-snap operation "switch"`)
}

func (s *snapsSuite) TestPostSnapsNoWeirdses(c *check.C) {
	s.daemonWithOverlordMockAndStore()

	// one could add more actions here ... 🤷
	for _, action := range []string{"install", "refresh", "remove"} {
		for weird, v := range map[string]string{
			"channel":      `"beta"`,
			"revision":     `"1"`,
			"devmode":      "true",
			"jailmode":     "true",
			"cohort-key":   `"what"`,
			"leave-cohort": "true",
			"prefer":       "true",
		} {
			buf := strings.NewReader(fmt.Sprintf(`{"action": "%s","snaps":["foo","bar"], "%s": %s}`, action, weird, v))
			req, err := http.NewRequest("POST", "/v2/snaps", buf)
			c.Assert(err, check.IsNil)
			req.Header.Set("Content-Type", "application/json")

			rspe := s.errorReq(c, req, nil, actionIsExpected)
			c.Check(rspe.Status, check.Equals, 400)
			c.Check(rspe.Message, testutil.Contains, `unsupported option provided for multi-snap operation`)
		}
	}
}

func (s *snapsSuite) TestPostSnapsOptionsUnsupportedActionError(c *check.C) {
	s.daemon(c)
	const expectedErr = "snapshot-options can only be specified for snapshot action"

	for _, action := range []string{"install", "refresh", "revert", "remove", "hold", "unhold",
		"enable", "disable", "switch", "xyzzy"} {
		holdParams := ""
		if action == "hold" {
			holdParams = `"time": "forever", "hold-level": "general",`
		}
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "snaps":["foo"], %s "snapshot-options": {}}`, action, holdParams))
		req, err := http.NewRequest("POST", "/v2/snaps", buf)
		c.Assert(err, check.IsNil)
		req.Header.Set("Content-Type", "application/json")

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestPostSnapsOptionsOtherErrors(c *check.C) {
	s.daemon(c)
	const notListedErr = `cannot use snapshot-options for snap "xyzzy" that is not listed in snaps`
	const invalidOptionsForSnapErr = `invalid snapshot-options for snap "bar":`

	testMap := map[string]struct {
		post          string
		expectedError string
	}{
		"snap-not-listed-valid-options": {`{"action": "snapshot", "snaps":["foo", "bar"], "snapshot-options": {"xyzzy": {"exclude":[""]}}}`, notListedErr},
		"snap-not-listed-exclude-empty": {`{"action": "snapshot", "snaps":["foo", "bar"], "snapshot-options": {"xyzzy": {"exclude":[]}}}`, notListedErr},
		"snap-not-listed-options-empty": {`{"action": "snapshot", "snaps":["foo", "bar"], "snapshot-options": {"xyzzy": {}}}`, notListedErr},
		"invalid-options-for-snap":      {`{"action": "snapshot", "snaps":["foo", "bar"], "snapshot-options": {"bar": {"exclude":["../"]}}}`, invalidOptionsForSnapErr},
	}

	for name, test := range testMap {
		buf := strings.NewReader(fmt.Sprint(test.post))
		req, err := http.NewRequest("POST", "/v2/snaps", buf)
		c.Assert(err, check.IsNil)
		req.Header.Set("Content-Type", "application/json")

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400)
		c.Check(rspe.Message, testutil.Contains, test.expectedError, check.Commentf("test: %q", name))
	}
}

func (s *snapsSuite) TestPostSnapsRemoveWithTerminate(c *check.C) {
	d := s.daemonWithOverlordMockAndStore()

	var snapstateRemoveCalled int
	defer daemon.MockSnapstateRemove(func(st *state.State, name string, revision snap.Revision, flags *snapstate.RemoveFlags) (*state.TaskSet, error) {
		snapstateRemoveCalled++
		c.Check(name, check.Equals, "foo")
		c.Check(flags.Terminate, check.Equals, true)
		t := st.NewTask("fake-remove", "Remove one")
		return state.NewTaskSet(t), nil
	})()

	buf := strings.NewReader(fmt.Sprintf(`{"action": "remove", "terminate":true}`))
	req, err := http.NewRequest("POST", "/v2/snaps/foo", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, check.Equals, 202)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Check(chg.Summary(), check.Equals, `Remove "foo" snap`)

	c.Assert(snapstateRemoveCalled, check.Equals, 1)
}

func (s *snapsSuite) TestPostSnapsRemoveManyWithTerminate(c *check.C) {
	d := s.daemonWithOverlordMockAndStore()

	var snapstateRemoveManyCalled int
	defer daemon.MockSnapstateRemoveMany(func(s *state.State, names []string, opts *snapstate.RemoveFlags) ([]string, []*state.TaskSet, error) {
		snapstateRemoveManyCalled++
		c.Check(names, check.HasLen, 2)
		c.Check(opts.Terminate, check.Equals, true)
		t := s.NewTask("fake-remove-2", "Remove two")
		return names, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	buf := strings.NewReader(fmt.Sprintf(`{"action": "remove", "snaps":["foo", "bar"], "terminate":true}`))
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, check.Equals, 202)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Check(chg.Summary(), check.Equals, `Remove snaps "foo", "bar"`)

	c.Assert(snapstateRemoveManyCalled, check.Equals, 1)
}

func (s *snapsSuite) TestPostSnapsRemoveManyWithPurge(c *check.C) {
	d := s.daemonWithOverlordMockAndStore()

	defer daemon.MockSnapstateRemoveMany(func(s *state.State, names []string, opts *snapstate.RemoveFlags) ([]string, []*state.TaskSet, error) {
		c.Check(names, check.HasLen, 2)
		c.Check(opts.Purge, check.Equals, true)
		t := s.NewTask("fake-remove-2", "Remove two")
		return names, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	buf := strings.NewReader(fmt.Sprintf(`{"action": "remove", "snaps":["foo", "bar"], "purge":true}`))
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, check.Equals, 202)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Check(chg.Summary(), check.Equals, `Remove snaps "foo", "bar"`)
}

func (s *snapsSuite) TestPostSnapsOptionsClean(c *check.C) {
	var snapshotSaveCalled int
	defer daemon.MockSnapshotSave(func(s *state.State, snaps, users []string,
		options map[string]*snap.SnapshotOptions) (uint64, []string, *state.TaskSet, error) {
		snapshotSaveCalled++

		c.Check(snaps, check.HasLen, 3)
		c.Check(snaps, check.DeepEquals, []string{"foo", "bar", "baz"})
		c.Check(options, check.HasLen, 1)
		c.Check(options, check.DeepEquals, map[string]*snap.SnapshotOptions{
			"foo": {Exclude: []string{"$SNAP_DATA/foo-path-1"}},
		})
		t := s.NewTask("fake-snapshot-2", "Snapshot two")
		return 1, snaps, state.NewTaskSet(t), nil
	})()

	s.daemonWithOverlordMockAndStore()
	buf := strings.NewReader(`{"action": "snapshot", "snaps": ["foo", "bar", "baz"],
	"snapshot-options": {"foo": {"exclude":["$SNAP_DATA/foo-path-1"]}, "bar":{"exclude":[]}, "baz":{}}}}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.asyncReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, check.Equals, 202)
	c.Check(snapshotSaveCalled, check.Equals, 1)
}

func (s *snapsSuite) TestPostSnapsOp(c *check.C) {
	systemRestartImmediate := s.testPostSnapsOp(c, "", "application/json")
	c.Check(systemRestartImmediate, check.Equals, false)
}

func (s *snapsSuite) TestPostSnapsOpMoreComplexContentType(c *check.C) {
	systemRestartImmediate := s.testPostSnapsOp(c, "", "application/json; charset=utf-8")
	c.Check(systemRestartImmediate, check.Equals, false)
}

func (s *snapsSuite) TestPostSnapsOpSystemRestartImmediate(c *check.C) {
	systemRestartImmediate := s.testPostSnapsOp(c, `"system-restart-immediate": true`, "application/json")
	c.Check(systemRestartImmediate, check.Equals, true)
}

func (s *snapsSuite) testPostSnapsOp(c *check.C, extraJSON, contentType string) (systemRestartImmediate bool) {
	defer daemon.MockAssertstateRefreshSnapAssertions(func(*state.State, int, *assertstate.RefreshAssertionsOptions) error { return nil })()
	defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		goal := g.(*storeUpdateGoalRecorder)
		c.Check(goal.snaps, check.HasLen, 0)
		t := s.NewTask("fake-refresh-all", "Refreshing everything")
		return []string{"fake1", "fake2"}, &snapstate.UpdateTaskSets{Refresh: []*state.TaskSet{state.NewTaskSet(t)}}, nil
	})()

	d := s.daemonWithOverlordMockAndStore()

	if extraJSON != "" {
		extraJSON = "," + extraJSON
	}
	buf := bytes.NewBufferString(fmt.Sprintf(`{"action": "refresh"%s}`, extraJSON))
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", contentType)

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Check(chg.Summary(), check.Equals, `Refresh snaps "fake1", "fake2"`)
	var apiData map[string]any
	c.Check(chg.Get("api-data", &apiData), check.IsNil)
	c.Check(apiData["snap-names"], check.DeepEquals, []any{"fake1", "fake2"})
	err = chg.Get("system-restart-immediate", &systemRestartImmediate)
	if err != nil && !errors.Is(err, state.ErrNoState) {
		c.Error(err)
	}
	return systemRestartImmediate
}

func (s *snapsSuite) TestPostSnapsOpInvalidCharset(c *check.C) {
	s.daemon(c)

	buf := bytes.NewBufferString(`{"action": "refresh"}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json; charset=iso-8859-1")

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, testutil.Contains, "unknown charset in content type")
}

func (s *snapsSuite) TestRefreshAll(c *check.C) {
	refreshSnapAssertions := false
	var refreshAssertionsOpts *assertstate.RefreshAssertionsOptions
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions = true
		refreshAssertionsOpts = opts
		return assertstate.RefreshSnapAssertions(s, userID, opts)
	})()

	d := s.daemon(c)

	for _, tst := range []struct {
		snaps []string
		msg   string
	}{
		{nil, "Refresh all snaps: no updates"},
		{[]string{"fake"}, `Refresh "fake" snap`},
		{[]string{"fake1", "fake2"}, `Refresh snaps "fake1", "fake2"`},
	} {
		refreshSnapAssertions = false
		refreshAssertionsOpts = nil

		defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
			goal := g.(*storeUpdateGoalRecorder)
			c.Check(goal.snaps, check.HasLen, 0)
			t := s.NewTask("fake-refresh-all", "Refreshing everything")
			return tst.snaps, &snapstate.UpdateTaskSets{Refresh: []*state.TaskSet{state.NewTaskSet(t)}}, nil
		})()

		inst := &daemon.SnapInstruction{Action: "refresh"}
		st := d.Overlord().State()
		st.Lock()
		res, err := inst.DispatchForMany()(context.Background(), inst, st)
		st.Unlock()
		c.Assert(err, check.IsNil)
		c.Check(res.Summary, check.Equals, tst.msg)
		c.Check(refreshSnapAssertions, check.Equals, true)
		c.Assert(refreshAssertionsOpts, check.NotNil)
		c.Check(refreshAssertionsOpts.IsRefreshOfAllSnaps, check.Equals, true)
	}
}

func (s *snapsSuite) TestRefreshAllNoChanges(c *check.C) {
	refreshSnapAssertions := false
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions = true
		return assertstate.RefreshSnapAssertions(s, userID, opts)
	})()

	defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		goal := g.(*storeUpdateGoalRecorder)
		c.Check(goal.snaps, check.HasLen, 0)
		return nil, &snapstate.UpdateTaskSets{Refresh: nil}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "refresh"}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Refresh all snaps: no updates`)
	c.Check(refreshSnapAssertions, check.Equals, true)
}

func (s *snapsSuite) TestRefreshAllRestoresValidationSets(c *check.C) {
	refreshSnapAssertions := false
	var refreshAssertionsOpts *assertstate.RefreshAssertionsOptions
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions = true
		refreshAssertionsOpts = opts
		return nil
	})()

	defer daemon.MockAssertstateRestoreValidationSetsTracking(func(s *state.State) error {
		return nil
	})()

	defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		return nil, nil, fmt.Errorf("boom")
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "refresh"}
	st := d.Overlord().State()
	st.Lock()
	_, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.ErrorMatches, "boom")
	c.Check(refreshSnapAssertions, check.Equals, true)
	c.Assert(refreshAssertionsOpts, check.NotNil)
	c.Check(refreshAssertionsOpts.IsRefreshOfAllSnaps, check.Equals, true)
}

func (s *snapsSuite) TestRefreshManyTransactionally(c *check.C) {
	var calledFlags *snapstate.Flags

	refreshSnapAssertions := false
	var refreshAssertionsOpts *assertstate.RefreshAssertionsOptions
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions = true
		refreshAssertionsOpts = opts
		return nil
	})()

	defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		goal := g.(*storeUpdateGoalRecorder)
		calledFlags = &opts.Flags
		c.Check(goal.snaps, check.HasLen, 2)
		t := s.NewTask("fake-refresh-2", "Refreshing two")

		return goal.names(), &snapstate.UpdateTaskSets{Refresh: []*state.TaskSet{state.NewTaskSet(t)}}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:      "refresh",
		Transaction: client.TransactionAllSnaps,
		Snaps:       []string{"foo", "bar"},
	}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Refresh snaps "foo", "bar"`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)
	c.Check(refreshSnapAssertions, check.Equals, true)
	c.Assert(refreshAssertionsOpts, check.NotNil)
	c.Check(refreshAssertionsOpts.IsRefreshOfAllSnaps, check.Equals, false)

	c.Check(calledFlags.Transaction, check.Equals, client.TransactionAllSnaps)
}

func (s *snapsSuite) TestRefreshMany(c *check.C) {
	refreshSnapAssertions := false
	var refreshAssertionsOpts *assertstate.RefreshAssertionsOptions
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions = true
		refreshAssertionsOpts = opts
		return nil
	})()

	defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		goal := g.(*storeUpdateGoalRecorder)
		c.Check(goal.snaps, check.HasLen, 2)
		t := s.NewTask("fake-refresh-2", "Refreshing two")
		return goal.names(), &snapstate.UpdateTaskSets{Refresh: []*state.TaskSet{state.NewTaskSet(t)}}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "refresh", Snaps: []string{"foo", "bar"}}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Refresh snaps "foo", "bar"`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)
	c.Check(refreshSnapAssertions, check.Equals, true)
	c.Assert(refreshAssertionsOpts, check.NotNil)
	c.Check(refreshAssertionsOpts.IsRefreshOfAllSnaps, check.Equals, false)
}

func (s *snapsSuite) TestRefreshManyIgnoreRunning(c *check.C) {
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	var calledFlags *snapstate.Flags
	defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		calledFlags = &opts.Flags

		goal := g.(*storeUpdateGoalRecorder)
		c.Check(goal.snaps, check.HasLen, 2)
		t := s.NewTask("fake-refresh-2", "Refreshing two")
		return goal.names(), &snapstate.UpdateTaskSets{Refresh: []*state.TaskSet{state.NewTaskSet(t)}}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:        "refresh",
		Snaps:         []string{"foo", "bar"},
		IgnoreRunning: true,
	}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Refresh snaps "foo", "bar"`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)
	c.Check(calledFlags.IgnoreRunning, check.Equals, true)
}

func (s *snapsSuite) TestRefreshMany1(c *check.C) {
	refreshSnapAssertions := false
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions = true
		return nil
	})()

	defer daemon.MockSnapstateUpdateWithGoal(func(_ context.Context, s *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		goal := g.(*storeUpdateGoalRecorder)
		c.Check(goal.snaps, check.HasLen, 1)
		t := s.NewTask("fake-refresh-1", "Refreshing one")
		return goal.names(), &snapstate.UpdateTaskSets{Refresh: []*state.TaskSet{state.NewTaskSet(t)}}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "refresh", Snaps: []string{"foo"}}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Refresh "foo" snap`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)
	c.Check(refreshSnapAssertions, check.Equals, true)
}

func storeSnapInfos(snaps []snapstate.StoreSnap) []*snap.Info {
	infos := make([]*snap.Info, 0, len(snaps))
	for _, sn := range snaps {
		name, key := snap.SplitInstanceName(sn.InstanceName)
		infos = append(infos, &snap.Info{
			SideInfo: snap.SideInfo{
				RealName: name,
			},
			InstanceKey: key,
		})
	}
	return infos
}

func (s *snapsSuite) TestInstallMany(c *check.C) {
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 2)

		t := st.NewTask("fake-install-2", "Install two")
		return storeSnapInfos(goal.snaps), []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "install", Snaps: []string{"foo", "bar"}}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Install snaps "foo", "bar"`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)
}

func (s *snapsSuite) TestInstallManyTransactionally(c *check.C) {
	var calledFlags snapstate.Flags
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		calledFlags = opts.Flags

		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 2)

		t := st.NewTask("fake-install-2", "Install two")
		return storeSnapInfos(goal.snaps), []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:      "install",
		Transaction: client.TransactionAllSnaps,
		Snaps:       []string{"foo", "bar"},
	}

	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Install snaps "foo", "bar"`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)

	c.Check(calledFlags.Transaction, check.Equals, client.TransactionAllSnaps)
}

func (s *snapsSuite) TestInstallManyEmptyName(c *check.C) {
	defer daemon.MockSnapstateInstallWithGoal(func(context.Context, *state.State, snapstate.InstallGoal, snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		return nil, nil, errors.New("should not be called")
	})()
	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "install", Snaps: []string{"", "bar"}}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(res, check.IsNil)
	c.Assert(err, check.ErrorMatches, "cannot install snap with empty name")
}

func (s *snapsSuite) TestRemoveMany(c *check.C) {
	defer daemon.MockSnapstateRemoveMany(func(s *state.State, names []string, opts *snapstate.RemoveFlags) ([]string, []*state.TaskSet, error) {
		c.Check(names, check.HasLen, 2)
		c.Check(opts.Purge, check.Equals, false)
		t := s.NewTask("fake-remove-2", "Remove two")
		return names, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "remove", Snaps: []string{"foo", "bar"}}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Remove snaps "foo", "bar"`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)
}

func (s *snapsSuite) TestRemoveManyWithPurge(c *check.C) {
	defer daemon.MockSnapstateRemoveMany(func(s *state.State, names []string, opts *snapstate.RemoveFlags) ([]string, []*state.TaskSet, error) {
		c.Check(names, check.HasLen, 2)
		c.Check(opts.Purge, check.Equals, true)
		t := s.NewTask("fake-remove-2", "Remove two")
		return names, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "remove", Purge: true, Snaps: []string{"foo", "bar"}}
	st := d.Overlord().State()
	st.Lock()
	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	st.Unlock()
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Remove snaps "foo", "bar"`)
	c.Check(res.Affected, check.DeepEquals, inst.Snaps)
}
func (s *snapsSuite) TestSnapInfoOneIntegration(c *check.C) {
	s.expectSnapsNameReadAccess()
	d := s.daemon(c)

	// we have v0 [r5] installed
	s.mkInstalledInState(c, d, "foo", "bar", "v0", snap.R(5), false, "")
	// and v1 [r10] is current
	s.mkInstalledInState(c, d, "foo", "bar", "v1", snap.R(10), true, `title: title
description: description
summary: summary
license: GPL-3.0
base: base18
apps:
  cmd:
    command: some.cmd
  cmd2:
    command: other.cmd
  cmd3:
    command: other.cmd
    common-id: org.foo.cmd
  svc1:
    command: somed1
    daemon: simple
  svc2:
    command: somed2
    daemon: forking
  svc3:
    command: somed3
    daemon: oneshot
  svc4:
    command: somed4
    daemon: notify
  svc5:
    command: some5
    timer: mon1,12:15
    daemon: simple
  svc6:
    command: some6
    daemon: simple
    sockets:
       sock:
         listen-stream: $SNAP_COMMON/run.sock
  svc7:
    command: some7
    daemon: simple
    sockets:
       other-sock:
         listen-stream: $SNAP_COMMON/other-run.sock
`)
	df := s.mkInstalledDesktopFile(c, "foo_cmd.desktop", "[Desktop]\nExec=foo.cmd %U")
	s.SysctlBufs = [][]byte{
		[]byte(`Type=simple
Id=snap.foo.svc1.service
Names=snap.foo.svc1.service
ActiveState=fumbling
UnitFileState=enabled
NeedDaemonReload=no
`),
		[]byte(`Type=forking
Id=snap.foo.svc2.service
Names=snap.foo.svc2.service
ActiveState=active
UnitFileState=disabled
NeedDaemonReload=no
`),
		[]byte(`Type=oneshot
Id=snap.foo.svc3.service
Names=snap.foo.svc3.service
ActiveState=reloading
UnitFileState=static
NeedDaemonReload=no
`),
		[]byte(`Type=notify
Id=snap.foo.svc4.service
Names=snap.foo.svc4.service
ActiveState=inactive
UnitFileState=potatoes
NeedDaemonReload=no
`),
		[]byte(`Type=simple
Id=snap.foo.svc5.service
Names=snap.foo.svc5.service
ActiveState=inactive
UnitFileState=static
NeedDaemonReload=no
`),
		[]byte(`Id=snap.foo.svc5.timer
Names=snap.foo.svc5.timer
ActiveState=active
UnitFileState=enabled
`),
		[]byte(`Type=simple
Id=snap.foo.svc6.service
Names=snap.foo.svc6.service
ActiveState=inactive
UnitFileState=static
NeedDaemonReload=no
`),
		[]byte(`Id=snap.foo.svc6.sock.socket
Names=snap.foo.svc6.sock.socket
ActiveState=active
UnitFileState=enabled
`),
		[]byte(`Type=simple
Id=snap.foo.svc7.service
Names=snap.foo.svc7.service
ActiveState=inactive
UnitFileState=static
NeedDaemonReload=no
`),
		[]byte(`Id=snap.foo.svc7.other-sock.socket
Names=snap.foo.svc7.other-sock.socket
ActiveState=inactive
UnitFileState=enabled
`),
	}

	var snapst snapstate.SnapState
	st := d.Overlord().State()
	st.Lock()
	st.Set("health", map[string]healthstate.HealthState{
		"foo": {Status: healthstate.OkayStatus},
	})
	err := snapstate.Get(st, "foo", &snapst)
	st.Unlock()
	c.Assert(err, check.IsNil)

	// modify state
	snapst.TrackingChannel = "beta"
	snapst.IgnoreValidation = true
	snapst.CohortKey = "some-long-cohort-key"
	st.Lock()
	snapstate.Set(st, "foo", &snapst)
	st.Unlock()

	req, err := http.NewRequest("GET", "/v2/snaps/foo", nil)
	c.Assert(err, check.IsNil)
	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Result, check.FitsTypeOf, &client.Snap{})
	m := rsp.Result.(*client.Snap)

	// installed-size depends on vagaries of the filesystem, just check type
	c.Check(m.InstalledSize, check.FitsTypeOf, int64(0))
	m.InstalledSize = 0
	// ditto install-date
	c.Check(m.InstallDate, check.FitsTypeOf, &time.Time{})
	m.InstallDate = nil

	expected := &daemon.RespJSON{
		Type:   daemon.ResponseTypeSync,
		Status: 200,
		Result: &client.Snap{
			ID:               "foo-id",
			Name:             "foo",
			Revision:         snap.R(10),
			Version:          "v1",
			Channel:          "stable",
			TrackingChannel:  "beta",
			IgnoreValidation: true,
			Title:            "title",
			Summary:          "summary",
			Description:      "description",
			Developer:        "bar",
			Publisher: &snap.StoreAccount{
				ID:          "bar-id",
				Username:    "bar",
				DisplayName: "Bar",
				Validation:  "unproven",
			},
			Status:      "active",
			Health:      &client.SnapHealth{Status: "okay"},
			Icon:        "/v2/icons/foo/icon",
			Type:        string(snap.TypeApp),
			Base:        "base18",
			Private:     false,
			DevMode:     false,
			JailMode:    false,
			Confinement: string(snap.StrictConfinement),
			TryMode:     false,
			MountedFrom: filepath.Join(dirs.SnapBlobDir, "foo_10.snap"),
			Apps: []client.AppInfo{
				{
					Snap: "foo", Name: "cmd",
					DesktopFile: df,
				}, {
					// no desktop file
					Snap: "foo", Name: "cmd2",
				}, {
					// has AppStream ID
					Snap: "foo", Name: "cmd3",
					CommonID: "org.foo.cmd",
				}, {
					// services
					Snap: "foo", Name: "svc1",
					Daemon:      "simple",
					DaemonScope: snap.SystemDaemon,
					Enabled:     true,
					Active:      false,
				}, {
					Snap: "foo", Name: "svc2",
					Daemon:      "forking",
					DaemonScope: snap.SystemDaemon,
					Enabled:     false,
					Active:      true,
				}, {
					Snap: "foo", Name: "svc3",
					Daemon:      "oneshot",
					DaemonScope: snap.SystemDaemon,
					Enabled:     true,
					Active:      true,
				}, {
					Snap: "foo", Name: "svc4",
					Daemon:      "notify",
					DaemonScope: snap.SystemDaemon,
					Enabled:     false,
					Active:      false,
				}, {
					Snap: "foo", Name: "svc5",
					Daemon:      "simple",
					DaemonScope: snap.SystemDaemon,
					Enabled:     true,
					Active:      false,
					Activators: []client.AppActivator{
						{Name: "svc5", Type: "timer", Active: true, Enabled: true},
					},
				}, {
					Snap: "foo", Name: "svc6",
					Daemon:      "simple",
					DaemonScope: snap.SystemDaemon,
					Enabled:     true,
					Active:      false,
					Activators: []client.AppActivator{
						{Name: "sock", Type: "socket", Active: true, Enabled: true},
					},
				}, {
					Snap: "foo", Name: "svc7",
					Daemon:      "simple",
					DaemonScope: snap.SystemDaemon,
					Enabled:     true,
					Active:      false,
					Activators: []client.AppActivator{
						{Name: "other-sock", Type: "socket", Active: false, Enabled: true},
					},
				},
			},
			Broken:    "",
			Contact:   "",
			License:   "GPL-3.0",
			CommonIDs: []string{"org.foo.cmd"},
			CohortKey: "some-long-cohort-key",
		},
	}

	c.Check(rsp.Result, check.DeepEquals, expected.Result)
}

func (s *snapsSuite) TestSnapInfoNotFound(c *check.C) {
	s.expectSnapsNameReadAccess()
	s.daemon(c)

	req, err := http.NewRequest("GET", "/v2/snaps/gfoo", nil)
	c.Assert(err, check.IsNil)
	c.Check(s.errorReq(c, req, nil, actionIsExpected).Status, check.Equals, 404)
}

func (s *snapsSuite) TestSnapInfoNoneFound(c *check.C) {
	s.expectSnapsNameReadAccess()
	s.daemon(c)

	req, err := http.NewRequest("GET", "/v2/snaps/gfoo", nil)
	c.Assert(err, check.IsNil)
	c.Check(s.errorReq(c, req, nil, actionIsExpected).Status, check.Equals, 404)
}

func (s *snapsSuite) TestSnapInfoIgnoresRemoteErrors(c *check.C) {
	s.expectSnapsNameReadAccess()
	s.daemon(c)
	s.err = errors.New("weird")

	req, err := http.NewRequest("GET", "/v2/snaps/gfoo", nil)
	c.Assert(err, check.IsNil)
	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 404)
	c.Check(rspe.Message, check.Not(check.Equals), "")
}

func (s *snapsSuite) TestSnapInfoReturnsHolds(c *check.C) {
	s.expectSnapsNameReadAccess()
	d := s.daemon(c)
	s.mkInstalledInState(c, d, "foo", "bar", "v0", snap.R(5), true, "")

	now := time.Now()
	userHold := now.Add(100 * 365 * 24 * time.Hour)
	restore := daemon.MockSystemHold(func(st *state.State, name string) (time.Time, error) {
		return userHold, nil
	})
	defer restore()

	gatingHold := now.Add(24 * time.Hour)
	restore = daemon.MockLongestGatingHold(func(st *state.State, name string) (time.Time, error) {
		return gatingHold, nil
	})
	defer restore()

	req, err := http.NewRequest("GET", "/v2/snaps/foo", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Result, check.FitsTypeOf, &client.Snap{})
	snapInfo := rsp.Result.(*client.Snap)

	testCmt := check.Commentf("expected user hold %s but got %s", userHold, snapInfo.Hold)
	c.Check(snapInfo.Hold.Equal(userHold), check.Equals, true, testCmt)

	testCmt = check.Commentf("expected gating hold %s but got %s", gatingHold, snapInfo.GatingHold)
	c.Check(snapInfo.GatingHold.Equal(gatingHold), check.Equals, true, testCmt)
}

func (s *snapsSuite) TestSnapManyInfosReturnsHolds(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)
	s.mkInstalledInState(c, d, "snap-a", "bar", "v0", snap.R(5), true, "")
	s.mkInstalledInState(c, d, "snap-b", "bar", "v0", snap.R(5), true, "")

	now := time.Now()
	userHold := now.Add(100 * 365 * 24 * time.Hour)
	restore := daemon.MockSystemHold(func(st *state.State, name string) (time.Time, error) {
		if name == "snap-a" {
			return userHold, nil
		}
		return time.Time{}, nil
	})
	defer restore()

	gatingHold := now.Add(24 * time.Hour)
	restore = daemon.MockLongestGatingHold(func(st *state.State, name string) (time.Time, error) {
		if name == "snap-b" {
			return gatingHold, nil
		}
		return time.Time{}, nil
	})
	defer restore()

	req, err := http.NewRequest("GET", "/v2/snaps", nil)
	c.Assert(err, check.IsNil)

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	snaps := snapList(rsp.Result)

	for _, snap := range snaps {
		switch snap["name"] {
		case "snap-a":
			c.Assert(snap["hold"], check.Equals, userHold.Format(time.RFC3339Nano))
			_, ok := snap["gating-hold"]
			c.Assert(ok, check.Equals, false)

		case "snap-b":
			c.Assert(snap["gating-hold"], check.Equals, gatingHold.Format(time.RFC3339Nano))
			_, ok := snap["hold"]
			c.Assert(ok, check.Equals, false)
		}
	}
}

func (s *snapsSuite) TestSnapInfoReturnsRefreshInhibitProceedTime(c *check.C) {
	s.expectSnapsNameReadAccess()
	d := s.daemon(c)
	s.mkInstalledInState(c, d, "foo", "bar", "v0", snap.R(5), true, "")

	st := d.Overlord().State()
	st.Lock()
	var snapst snapstate.SnapState
	// Update snap state with RefreshInhibitedTime.
	c.Assert(snapstate.Get(st, "foo", &snapst), check.IsNil)
	refreshInhibitTime := time.Now().Add(1 * time.Hour)
	snapst.RefreshInhibitedTime = &refreshInhibitTime
	snapstate.Set(st, "foo", &snapst)
	// Get expected proceed time while we have the lock.
	expectedProceedTime := snapst.RefreshInhibitProceedTime(st)

	monitored := map[string]context.CancelFunc{"foo": func() {}}
	st.Cache("monitored-snaps", monitored)
	st.Unlock()

	req, err := http.NewRequest("GET", "/v2/snaps/foo", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Result, check.FitsTypeOf, &client.Snap{})
	snapInfo := rsp.Result.(*client.Snap)
	c.Assert(snapInfo.RefreshInhibit, check.NotNil)

	c.Check(snapInfo.RefreshInhibit.ProceedTime.Equal(expectedProceedTime), check.Equals, true)
}

func (s *snapsSuite) TestSnapInfoRefreshInhibitProceedTimeLP2089195(c *check.C) {
	s.expectSnapsNameReadAccess()
	d := s.daemon(c)
	// RefreshInhibitedTime is nil by default
	s.mkInstalledInState(c, d, "foo", "bar", "v0", snap.R(5), true, "")

	st := d.Overlord().State()
	st.Lock()
	// Mark monitored while RefreshInhibitedTime is nil
	monitored := map[string]context.CancelFunc{"foo": func() {}}
	st.Cache("monitored-snaps", monitored)
	st.Unlock()

	req, err := http.NewRequest("GET", "/v2/snaps/foo", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Result, check.FitsTypeOf, &client.Snap{})
	snapInfo := rsp.Result.(*client.Snap)
	c.Assert(snapInfo.RefreshInhibit, check.IsNil)
}

func (s *snapsSuite) TestSnapManyInfosReturnsRefreshInhibitProceedTime(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)
	s.mkInstalledInState(c, d, "snap-a", "bar", "v0", snap.R(5), true, "")
	s.mkInstalledInState(c, d, "snap-b", "bar", "v0", snap.R(5), true, "")
	s.mkInstalledInState(c, d, "snap-c", "bar", "v0", snap.R(5), true, "")

	st := d.Overlord().State()
	st.Lock()
	var snapst snapstate.SnapState

	// Update snap-a state with RefreshInhibitedTime.
	c.Assert(snapstate.Get(st, "snap-a", &snapst), check.IsNil)
	refreshInhibitTime := time.Now().Add(1 * time.Hour)
	snapst.RefreshInhibitedTime = &refreshInhibitTime
	snapstate.Set(st, "snap-a", &snapst)
	// Get expected proceed time for snap-a while we have the lock.
	expectedProceedTimeA := snapst.RefreshInhibitProceedTime(st)

	// Update snap-b state with RefreshInhibitedTime.
	c.Assert(snapstate.Get(st, "snap-b", &snapst), check.IsNil)
	refreshInhibitTime = time.Now().Add(1 * time.Hour)
	snapst.RefreshInhibitedTime = &refreshInhibitTime
	snapstate.Set(st, "snap-b", &snapst)
	// Get expected proceed time for snap-b while we have the lock.
	expectedProceedTimeB := snapst.RefreshInhibitProceedTime(st)

	monitored := map[string]context.CancelFunc{
		"snap-a": func() {},
		// Simulate a scenario where a refresh is continued (i.e. snap is
		// not monitored) but RefreshInhibitedTime is not reset yet.
		"snap-b": nil,
	}
	st.Cache("monitored-snaps", monitored)

	st.Unlock()

	req, err := http.NewRequest("GET", "/v2/snaps", nil)
	c.Assert(err, check.IsNil)

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	snaps := snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 3)

	for _, snap := range snaps {
		testCmt := check.Commentf("snap %s failed", snap["name"])
		switch snap["name"] {
		case "snap-a":
			refreshInhibit := snap["refresh-inhibit"].(map[string]any)
			proceedTime, err := time.Parse(time.RFC3339Nano, refreshInhibit["proceed-time"].(string))
			c.Assert(err, check.IsNil)
			c.Assert(proceedTime.Equal(expectedProceedTimeA), check.Equals, true, testCmt)
		case "snap-b":
			refreshInhibit := snap["refresh-inhibit"].(map[string]any)
			proceedTime, err := time.Parse(time.RFC3339Nano, refreshInhibit["proceed-time"].(string))
			c.Assert(err, check.IsNil)
			c.Assert(proceedTime.Equal(expectedProceedTimeB), check.Equals, true, testCmt)
		case "snap-c":
			_, ok := snap["refresh-inhibit"]
			c.Assert(ok, check.Equals, false)
		}
	}
}

func (s *snapsSuite) TestSnapManyInfosSelectRefreshInhibited(c *check.C) {
	s.expectSnapsReadAccess()
	d := s.daemon(c)
	s.mkInstalledInState(c, d, "snap-a", "bar", "v0", snap.R(5), true, "")
	s.mkInstalledInState(c, d, "snap-b", "bar", "v0", snap.R(5), true, "")
	s.mkInstalledInState(c, d, "snap-c", "bar", "v0", snap.R(5), true, "")

	st := d.Overlord().State()
	st.Lock()
	var snapst snapstate.SnapState

	// Update snap-a state with RefreshInhibitedTime.
	c.Assert(snapstate.Get(st, "snap-a", &snapst), check.IsNil)
	refreshInhibitTime := time.Now().Add(1 * time.Hour)
	snapst.RefreshInhibitedTime = &refreshInhibitTime
	snapstate.Set(st, "snap-a", &snapst)
	// Get expected proceed time for snap-a while we have the lock.
	expectedProceedTimeA := snapst.RefreshInhibitProceedTime(st)

	// Update snap-b state with RefreshInhibitedTime.
	c.Assert(snapstate.Get(st, "snap-b", &snapst), check.IsNil)
	// Simulate a scenario where proceed time is in the past but the snap is still monitored
	refreshInhibitTime = time.Now().Add(-30 * 24 * time.Hour)
	snapst.RefreshInhibitedTime = &refreshInhibitTime
	snapstate.Set(st, "snap-b", &snapst)
	// Get expected proceed time for snap-a while we have the lock.
	expectedProceedTimeB := snapst.RefreshInhibitProceedTime(st)

	monitored := map[string]context.CancelFunc{
		"snap-a": func() {},
		// Snap monitored should show as inhibited even when proceed-time is in the past
		"snap-b": func() {},
	}
	st.Cache("monitored-snaps", monitored)

	st.Unlock()

	req, err := http.NewRequest("GET", "/v2/snaps?select=refresh-inhibited", nil)
	c.Assert(err, check.IsNil)

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	snaps := snapList(rsp.Result)
	c.Assert(snaps, check.HasLen, 2)

	for _, snap := range snaps {
		testCmt := check.Commentf("snap %s failed", snap["name"])
		switch snap["name"] {
		case "snap-a":
			refreshInhibit := snap["refresh-inhibit"].(map[string]any)
			proceedTime, err := time.Parse(time.RFC3339Nano, refreshInhibit["proceed-time"].(string))
			c.Assert(err, check.IsNil)
			c.Assert(proceedTime.Equal(expectedProceedTimeA), check.Equals, true, testCmt)
		case "snap-b":
			refreshInhibit := snap["refresh-inhibit"].(map[string]any)
			proceedTime, err := time.Parse(time.RFC3339Nano, refreshInhibit["proceed-time"].(string))
			c.Assert(err, check.IsNil)
			c.Assert(proceedTime.Equal(expectedProceedTimeB), check.Equals, true, testCmt)
		case "snap-c":
			c.Error("snap-c should not be listed")
		}
	}
}

func (s *snapsSuite) TestSnapInfoReturnsRefreshFailures(c *check.C) {
	s.expectSnapsNameReadAccess()
	d := s.daemon(c)
	s.mkInstalledInState(c, d, "foo", "bar", "v0", snap.R(5), true, "")

	expectedRefreshFailures := &snap.RefreshFailuresInfo{
		Revision:            snap.R(6),
		FailureCount:        4,
		LastFailureTime:     time.Date(2024, time.October, 10, 21, 22, 11, 0, time.UTC),
		LastFailureSeverity: snap.RefreshFailureSeverityAfterReboot,
	}

	st := d.Overlord().State()
	st.Lock()
	var snapst snapstate.SnapState
	// Update snap state with RefreshFailure.
	c.Assert(snapstate.Get(st, "foo", &snapst), check.IsNil)
	snapst.RefreshFailures = expectedRefreshFailures
	snapstate.Set(st, "foo", &snapst)
	st.Unlock()

	req, err := http.NewRequest("GET", "/v2/snaps/foo", nil)
	c.Assert(err, check.IsNil)

	rsp := s.syncReq(c, req, nil, actionIsExpected)

	c.Assert(rsp.Result, check.FitsTypeOf, &client.Snap{})
	snapInfo := rsp.Result.(*client.Snap)
	c.Assert(snapInfo.RefreshFailures, check.NotNil)

	c.Check(snapInfo.RefreshFailures, check.DeepEquals, expectedRefreshFailures)
}

func (s *snapsSuite) TestMapLocalFields(c *check.C) {
	media := snap.MediaInfos{
		{
			Type: "screenshot",
			URL:  "https://example.com/shot1.svg",
		}, {
			Type: "icon",
			URL:  "https://example.com/icon.png",
		}, {
			Type: "screenshot",
			URL:  "https://example.com/shot2.svg",
		},
	}

	publisher := snap.StoreAccount{
		ID:          "some-dev-id",
		Username:    "some-dev",
		DisplayName: "Some Developer",
		Validation:  "poor",
	}
	info := &snap.Info{
		SideInfo: snap.SideInfo{
			SnapID:            "some-snap-id",
			RealName:          "some-snap",
			EditedTitle:       "A Title",
			EditedSummary:     "a summary",
			EditedDescription: "the\nlong\ndescription",
			Channel:           "bleeding/edge",
			EditedLinks: map[string][]string{
				"contact": {"mailto:alice@example.com"},
			},
			LegacyEditedContact: "mailto:alice@example.com",
			Revision:            snap.R(7),
			Private:             true,
		},
		InstanceKey: "instance",
		SnapType:    "app",
		Base:        "the-base",
		Version:     "v1.0",
		License:     "MIT",
		Broken:      "very",
		Confinement: "very strict",
		CommonIDs:   []string{"foo", "bar"},
		Media:       media,
		DownloadInfo: snap.DownloadInfo{
			Size:     42,
			Sha3_384: "some-sum",
		},
		Publisher: publisher,
	}

	// make InstallDate work
	c.Assert(os.MkdirAll(info.MountDir(), 0755), check.IsNil)
	c.Assert(os.Symlink("7", filepath.Join(info.MountDir(), "..", "current")), check.IsNil)

	info.Apps = map[string]*snap.AppInfo{
		"foo": {Snap: info, Name: "foo", Command: "foo"},
		"bar": {Snap: info, Name: "bar", Command: "bar"},
	}
	about := daemon.MakeAboutSnap(info, &snapstate.SnapState{
		Active:          true,
		TrackingChannel: "flaky/beta",
		Current:         snap.R(7),
		Flags: snapstate.Flags{
			IgnoreValidation: true,
			DevMode:          true,
			JailMode:         true,
		},
	},
	)

	expected := &client.Snap{
		ID:               "some-snap-id",
		Name:             "some-snap_instance",
		Summary:          "a summary",
		Description:      "the\nlong\ndescription",
		Developer:        "some-dev",
		Publisher:        &publisher,
		Icon:             "https://example.com/icon.png",
		Type:             "app",
		Base:             "the-base",
		Version:          "v1.0",
		Revision:         snap.R(7),
		Channel:          "bleeding/edge",
		TrackingChannel:  "flaky/beta",
		InstallDate:      info.InstallDate(),
		InstalledSize:    42,
		Status:           "active",
		Confinement:      "very strict",
		IgnoreValidation: true,
		DevMode:          true,
		JailMode:         true,
		Private:          true,
		Broken:           "very",
		Links: map[string][]string{
			"contact": {"mailto:alice@example.com"},
		},
		Contact:     "mailto:alice@example.com",
		Title:       "A Title",
		License:     "MIT",
		CommonIDs:   []string{"foo", "bar"},
		MountedFrom: filepath.Join(dirs.SnapBlobDir, "some-snap_instance_7.snap"),
		Media:       media,
		Apps: []client.AppInfo{
			{Snap: "some-snap_instance", Name: "bar"},
			{Snap: "some-snap_instance", Name: "foo"},
		},
	}
	c.Check(daemon.MapLocal(about, nil), check.DeepEquals, expected)
}

func (s *snapsSuite) TestMapLocalFieldsWithComponents(c *check.C) {
	dirs.SetRootDir(c.MkDir())
	defer dirs.SetRootDir(dirs.GlobalRootDir)

	media := snap.MediaInfos{
		{
			Type: "screenshot",
			URL:  "https://example.com/shot1.svg",
		}, {
			Type: "icon",
			URL:  "https://example.com/icon.png",
		}, {
			Type: "screenshot",
			URL:  "https://example.com/shot2.svg",
		},
	}

	publisher := snap.StoreAccount{
		ID:          "some-dev-id",
		Username:    "some-dev",
		DisplayName: "Some Developer",
		Validation:  "poor",
	}
	info := &snap.Info{
		SideInfo: snap.SideInfo{
			SnapID:            "some-snap-id",
			RealName:          "some-snap",
			EditedTitle:       "A Title",
			EditedSummary:     "a summary",
			EditedDescription: "the\nlong\ndescription",
			Channel:           "bleeding/edge",
			EditedLinks: map[string][]string{
				"contact": {"mailto:alice@example.com"},
			},
			LegacyEditedContact: "mailto:alice@example.com",
			Revision:            snap.R(7),
			Private:             true,
		},
		SnapType:    "app",
		Base:        "the-base",
		Version:     "v1.0",
		License:     "MIT",
		Broken:      "very",
		Confinement: "very strict",
		CommonIDs:   []string{"foo", "bar"},
		Media:       media,
		DownloadInfo: snap.DownloadInfo{
			Size:     42,
			Sha3_384: "some-sum",
		},
		Publisher: publisher,
		Components: map[string]*snap.Component{
			"comp-1": {
				Name: "comp-1",
				Type: "standard",
			},
			"comp-2": {
				Name:        "comp-2",
				Type:        "standard",
				Summary:     "summary 2",
				Description: "description 2",
			},
			"comp-3": {
				Name:        "comp-3",
				Type:        "standard",
				Summary:     "summary 3",
				Description: "description 3",
			},
			"comp-4": {
				Name: "comp-4",
				Type: "standard",
			},
		},
	}

	// make InstallDate work
	c.Assert(os.MkdirAll(info.MountDir(), 0755), check.IsNil)
	c.Assert(os.Symlink("7", filepath.Join(info.MountDir(), "..", "current")), check.IsNil)

	info.Apps = map[string]*snap.AppInfo{
		"foo": {Snap: info, Name: "foo", Command: "foo"},
		"bar": {Snap: info, Name: "bar", Command: "bar"},
	}

	const comp1yaml = `
component: some-snap+comp-1
type: standard
`
	const comp2yaml = `
component: some-snap+comp-2
type: standard
version: 1.0
summary: summary 2
description: description 2
`
	// We need just enough info for components in snap.yaml
	const snapYaml = `
name: some-snap
version: 1
components:
  comp-1:
    type: standard
  comp-2:
    type: standard
`

	// Mock snap.yaml/component.yaml files for installed components
	ssi := &snap.SideInfo{RealName: "some-snap", Revision: snap.R(7),
		SnapID: "some-snap-id"}
	snaptest.MockSnap(c, snapYaml, ssi)
	csi := snap.NewComponentSideInfo(naming.NewComponentRef("some-snap", "comp-1"), snap.R(33))
	snaptest.MockComponent(c, comp1yaml, info, *csi)
	csi2 := snap.NewComponentSideInfo(naming.NewComponentRef("some-snap", "comp-2"), snap.R(34))
	snaptest.MockComponent(c, comp2yaml, info, *csi2)
	comps := []*sequence.ComponentState{
		sequence.NewComponentState(csi, snap.StandardComponent),
		sequence.NewComponentState(csi2, snap.StandardComponent),
	}

	// make InstallDate/InstalledSize work for comp1 and comp2
	cpi := snap.MinimalComponentContainerPlaceInfo(
		csi.Component.ComponentName, csi.Revision, "some-snap")
	symLn := snap.ComponentLinkPath(cpi, snap.R(7))
	c.Assert(os.MkdirAll(cpi.MountDir(), 0755), check.IsNil)
	os.WriteFile(cpi.MountFile(), []byte{0, 0}, 0644)
	c.Assert(os.MkdirAll(filepath.Dir(symLn), 0755), check.IsNil)
	c.Assert(os.Symlink(cpi.MountDir(), symLn), check.IsNil)
	cpi2 := snap.MinimalComponentContainerPlaceInfo(
		csi2.Component.ComponentName, csi2.Revision, "some-snap")
	symLn2 := snap.ComponentLinkPath(cpi2, snap.R(7))
	c.Assert(os.MkdirAll(cpi2.MountDir(), 0755), check.IsNil)
	os.WriteFile(cpi2.MountFile(), []byte{0, 0, 0}, 0644)
	c.Assert(os.MkdirAll(filepath.Dir(symLn2), 0755), check.IsNil)
	c.Assert(os.Symlink(cpi2.MountDir(), symLn2), check.IsNil)

	about := daemon.MakeAboutSnap(info, &snapstate.SnapState{
		Sequence: snapstatetest.NewSequenceFromRevisionSideInfos(
			[]*sequence.RevisionSideState{
				sequence.NewRevisionSideState(ssi, comps)}),
		Active:          true,
		TrackingChannel: "flaky/beta",
		Current:         snap.R(7),
		Flags: snapstate.Flags{
			IgnoreValidation: true,
			DevMode:          true,
			JailMode:         true,
		},
	},
	)

	expected := &client.Snap{
		ID:               "some-snap-id",
		Name:             "some-snap",
		Summary:          "a summary",
		Description:      "the\nlong\ndescription",
		Developer:        "some-dev",
		Publisher:        &publisher,
		Icon:             "https://example.com/icon.png",
		Type:             "app",
		Base:             "the-base",
		Version:          "v1.0",
		Revision:         snap.R(7),
		Channel:          "bleeding/edge",
		TrackingChannel:  "flaky/beta",
		InstallDate:      info.InstallDate(),
		InstalledSize:    42,
		Status:           "active",
		Confinement:      "very strict",
		IgnoreValidation: true,
		DevMode:          true,
		JailMode:         true,
		Private:          true,
		Broken:           "very",
		Links: map[string][]string{
			"contact": {"mailto:alice@example.com"},
		},
		Contact:     "mailto:alice@example.com",
		Title:       "A Title",
		License:     "MIT",
		CommonIDs:   []string{"foo", "bar"},
		MountedFrom: filepath.Join(dirs.SnapBlobDir, "some-snap_7.snap"),
		Media:       media,
		Apps: []client.AppInfo{
			{Snap: "some-snap", Name: "bar"},
			{Snap: "some-snap", Name: "foo"},
		},
		Components: []client.Component{
			// comp-1 has the snap version as it did not specify a version itself
			{Name: "comp-1", Type: "standard", Version: "v1.0", Revision: snap.R(33),
				InstallDate: snap.ComponentInstallDate(cpi, snap.R(7)), InstalledSize: 2},
			{Name: "comp-2", Type: "standard", Version: "1.0", Revision: snap.R(34),
				Summary: "summary 2", Description: "description 2",
				InstallDate: snap.ComponentInstallDate(cpi2, snap.R(7)), InstalledSize: 3},
			{Name: "comp-3", Type: "standard",
				Summary: "summary 3", Description: "description 3"},
			{Name: "comp-4", Type: "standard"},
		},
	}
	c.Check(daemon.MapLocal(about, nil), check.DeepEquals, expected)
}

func (s *snapsSuite) TestMapLocalOfTryResolvesSymlink(c *check.C) {
	c.Assert(os.MkdirAll(dirs.SnapBlobDir, 0755), check.IsNil)

	info := snap.Info{SideInfo: snap.SideInfo{RealName: "hello", Revision: snap.R(1)}}
	snapst := snapstate.SnapState{}
	mountFile := info.MountFile()
	about := daemon.MakeAboutSnap(&info, &snapst)

	// if not a 'try', then MountedFrom is just MountFile()
	c.Check(daemon.MapLocal(about, nil).MountedFrom, check.Equals, mountFile)

	// if it's a try, then MountedFrom resolves the symlink
	// (note it doesn't matter, here, whether the target of the link exists)
	snapst.TryMode = true
	c.Assert(os.Symlink("/xyzzy", mountFile), check.IsNil)
	c.Check(daemon.MapLocal(about, nil).MountedFrom, check.Equals, "/xyzzy")

	// if the readlink fails, it's unset
	c.Assert(os.Remove(mountFile), check.IsNil)
	c.Check(daemon.MapLocal(about, nil).MountedFrom, check.Equals, "")
}

func (s *snapsSuite) TestPostSnapBadRequest(c *check.C) {
	s.daemon(c)

	buf := bytes.NewBufferString(`hello`)
	req, err := http.NewRequest("POST", "/v2/snaps/hello-world", buf)
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, check.Not(check.Equals), "")
}

func (s *snapsSuite) TestPostSnapBadAction(c *check.C) {
	s.daemon(c)

	buf := bytes.NewBufferString(`{"action": "potato"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/hello-world", buf)
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsUnexpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, check.Not(check.Equals), "")
}

func (s *snapsSuite) TestPostSnapBadChannel(c *check.C) {
	s.daemon(c)

	buf := bytes.NewBufferString(`{"channel": "1/2/3/4"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/hello-world", buf)
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, check.Not(check.Equals), "")
}

func (s *snapsSuite) TestPostSnap(c *check.C) {
	checkOpts := func(opts *snapstate.RevisionOptions) {
		// no channel in -> no channel out
		c.Check(opts.Channel, check.Equals, "")
	}
	summary, systemRestartImmediate := s.testPostSnap(c, "", checkOpts)
	c.Check(summary, check.Equals, `Install "foo" snap`)
	c.Check(systemRestartImmediate, check.Equals, false)
}

func (s *snapsSuite) TestPostSnapWithChannel(c *check.C) {
	checkOpts := func(opts *snapstate.RevisionOptions) {
		// channel in -> channel out
		c.Check(opts.Channel, check.Equals, "xyzzy")
	}
	summary, systemRestartImmediate := s.testPostSnap(c, `"channel": "xyzzy"`, checkOpts)
	c.Check(summary, check.Equals, `Install "foo" snap from "xyzzy" channel`)
	c.Check(systemRestartImmediate, check.Equals, false)
}

func (s *snapsSuite) TestPostSnapSystemRestartImmediate(c *check.C) {
	_, systemRestartImmediate := s.testPostSnap(c, `"system-restart-immediate": true`, nil)
	c.Check(systemRestartImmediate, check.Equals, true)
}

func (s *snapsSuite) testPostSnap(c *check.C, extraJSON string, checkOpts func(opts *snapstate.RevisionOptions)) (summary string, systemRestartImmediate bool) {
	d := s.daemonWithOverlordMock()

	soon := 0
	var origEnsureStateSoon func(*state.State)
	origEnsureStateSoon, restore := daemon.MockEnsureStateSoon(func(st *state.State) {
		soon++
		origEnsureStateSoon(st)
	})
	defer restore()

	checked := false
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 1)

		if checkOpts != nil {
			checkOpts(&goal.snaps[0].RevOpts)
		}
		checked = true
		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	var buf *bytes.Buffer
	if extraJSON != "" {
		extraJSON = "," + extraJSON
	}
	buf = bytes.NewBufferString(fmt.Sprintf(`{"action": "install"%s}`, extraJSON))
	req, err := http.NewRequest("POST", "/v2/snaps/foo", buf)
	c.Assert(err, check.IsNil)

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	var names []string
	err = chg.Get("snap-names", &names)
	c.Assert(err, check.IsNil)
	c.Check(names, check.DeepEquals, []string{"foo"})

	c.Check(checked, check.Equals, true)
	c.Check(soon, check.Equals, 1)
	c.Check(chg.Tasks()[0].Summary(), check.Equals, "Doing a fake install")

	var apiData map[string]any
	c.Check(chg.Get("api-data", &apiData), check.IsNil)
	c.Check(apiData["snap-names"], check.DeepEquals, []any{"foo"})

	summary = chg.Summary()
	err = chg.Get("system-restart-immediate", &systemRestartImmediate)
	if err != nil && !errors.Is(err, state.ErrNoState) {
		c.Error(err)
	}
	return summary, systemRestartImmediate
}

func (s *snapsSuite) TestPostSnapVerifySnapInstruction(c *check.C) {
	s.daemonWithOverlordMock()

	buf := bytes.NewBufferString(`{"action": "install"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/ubuntu-core", buf)
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, testutil.Contains, `cannot install "ubuntu-core", please use "core" instead`)
}

func (s *snapsSuite) TestPostSnapCohortUnsupportedAction(c *check.C) {
	s.daemonWithOverlordMock()
	const expectedErr = "cohort-key can only be specified for install, refresh, or switch"

	for _, action := range []string{"remove", "revert", "enable", "disable", "xyzzy"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "cohort-key": "32"}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestPostSnapQuotaGroupWrongAction(c *check.C) {
	s.daemonWithOverlordMock()
	const expectedErr = "quota-group can only be specified on install"

	for _, action := range []string{"remove", "refresh", "revert", "enable", "disable", "xyzzy"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "quota-group": "foo"}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestPostSnapLeaveCohortUnsupportedAction(c *check.C) {
	s.daemonWithOverlordMock()
	const expectedErr = "leave-cohort can only be specified for refresh or switch"

	for _, action := range []string{"install", "remove", "revert", "enable", "disable", "xyzzy"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "leave-cohort": true}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestPostSnapPreferWrongAction(c *check.C) {
	s.daemonWithOverlordMock()
	const expectedErr = "the prefer flag can only be specified on install"

	for _, action := range []string{"remove", "refresh", "revert", "enable", "disable", "xyzzy"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "prefer": true}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestPostSnapTerminateWrongAction(c *check.C) {
	s.daemonWithOverlordMock()
	const expectedErr = `terminate can only be specified for the "remove" action`

	for _, action := range []string{"install", "refresh", "revert", "enable", "disable", "xyzzy"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "terminate": true}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestPostSnapTerminateWithRevisionSet(c *check.C) {
	s.daemonWithOverlordMock()

	defer daemon.MockSnapstateRemove(func(st *state.State, name string, revision snap.Revision, flags *snapstate.RemoveFlags) (*state.TaskSet, error) {
		c.Check(name, check.Equals, "some-snap")
		c.Check(flags.Terminate, check.Equals, true)
		t := st.NewTask("fake-remove", "Remove one")
		return state.NewTaskSet(t), nil
	})()

	const expectedErr = `terminate can only be specified when revision is unset`

	buf := strings.NewReader(`{"action": "remove", "terminate": true, "revision": "42"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, check.Equals, expectedErr)
}

func (s *snapsSuite) TestPostSnapCohortIncompat(c *check.C) {
	s.daemonWithOverlordMock()
	type T struct {
		opts   string
		errmsg string
	}

	for i, t := range []T{
		// TODO: more?
		{`"cohort-key": "what", "revision": "42"`, `cannot specify both cohort-key and revision`},
		{`"cohort-key": "what", "leave-cohort": true`, `cannot specify both cohort-key and leave-cohort`},
	} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "refresh", %s}`, t.opts))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil, check.Commentf("%d (%s)", i, t.opts))

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%d (%s)", i, t.opts))
		c.Check(rspe.Message, check.Equals, t.errmsg, check.Commentf("%d (%s)", i, t.opts))
	}
}

func (s *snapsSuite) TestPostSnapSetsUser(c *check.C) {
	d := s.daemon(c)

	_, restore := daemon.MockEnsureStateSoon(func(st *state.State) {})
	defer restore()

	checked := false
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		c.Check(opts.UserID, check.Equals, 1)
		checked = true
		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	state := d.Overlord().State()
	state.Lock()
	user, err := auth.NewUser(state, auth.NewUserParams{
		Username:   "username",
		Email:      "email@test.com",
		Macaroon:   "macaroon",
		Discharges: []string{"discharge"},
	})
	state.Unlock()
	c.Check(err, check.IsNil)

	buf := bytes.NewBufferString(`{"action": "install"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/hello-world", buf)
	c.Assert(err, check.IsNil)

	rsp := s.asyncReq(c, req, user, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)
	c.Check(checked, check.Equals, true)
}

func (s *snapsSuite) TestPostSnapEnableDisableSwitchRevision(c *check.C) {
	s.daemon(c)

	for _, action := range []string{"enable", "disable", "switch"} {
		buf := bytes.NewBufferString(`{"action": "` + action + `", "revision": "42"}`)
		req, err := http.NewRequest("POST", "/v2/snaps/hello-world", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400)
		c.Check(rspe.Message, testutil.Contains, "takes no revision")
	}
}

func (s *snapsSuite) TestPostSnapOptionsUnsupportedAction(c *check.C) {
	s.daemon(c)
	const expectedErr = "snapshot-options can only be specified for snapshot action"

	for _, action := range []string{"install", "refresh", "revert", "enable", "disable", "switch", "xyzzy"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "snapshot-options": {}}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/foo", buf)
		c.Assert(err, check.IsNil)
		req.Header.Set("Content-Type", "application/json")

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestInstall(c *check.C) {
	var calledName string

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 1)

		calledName = goal.snaps[0].InstanceName

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action: "install",
		// Install the snap in developer mode
		DevMode: true,
		Snaps:   []string{"fake"},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)
	c.Check(calledName, check.Equals, "fake")
}

func (s *snapsSuite) TestInstallWithQuotaGroup(c *check.C) {
	var calledFlags snapstate.Flags

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		calledFlags = opts.Flags

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:         "install",
		Snaps:          []string{"fake"},
		QuotaGroupName: "test-group",
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)
	c.Check(calledFlags.QuotaGroupName, check.Equals, "test-group")
}

func (s *snapsSuite) TestInstallDevMode(c *check.C) {
	var calledFlags snapstate.Flags

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		calledFlags = opts.Flags

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action: "install",
		// Install the snap in developer mode
		DevMode: true,
		Snaps:   []string{"fake"},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	c.Check(calledFlags.DevMode, check.Equals, true)
}

func (s *snapsSuite) TestInstallJailMode(c *check.C) {
	var calledFlags snapstate.Flags

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		calledFlags = opts.Flags

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:   "install",
		JailMode: true,
		Snaps:    []string{"fake"},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	c.Check(calledFlags.JailMode, check.Equals, true)
}

func (s *snapsSuite) TestInstallJailModeDevModeOS(c *check.C) {
	restore := sandbox.MockForceDevMode(true)
	defer restore()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:   "install",
		JailMode: true,
		Snaps:    []string{"foo"},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.ErrorMatches, "this system cannot honour the jailmode flag")
}

func (s *snapsSuite) TestInstallJailModeDevMode(c *check.C) {
	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:   "install",
		DevMode:  true,
		JailMode: true,
		Snaps:    []string{"foo"},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.ErrorMatches, "cannot use devmode and jailmode flags together")
}

func (s *snapsSuite) TestInstallCohort(c *check.C) {
	var calledName string
	var calledCohort string

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 1)

		calledName = goal.snaps[0].InstanceName
		calledCohort = goal.snaps[0].RevOpts.CohortKey

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action: "install",
		Snaps:  []string{"fake"},
	}
	inst.CohortKey = "To the legion of the lost ones, to the cohort of the damned."

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)
	c.Check(calledName, check.Equals, "fake")
	c.Check(calledCohort, check.Equals, "To the legion of the lost ones, to the cohort of the damned.")
	c.Check(res.Summary, check.Equals, `Install "fake" snap from "…e damned." cohort`)
}

func (s *snapsSuite) TestInstallIgnoreValidation(c *check.C) {
	var calledFlags snapstate.Flags
	installQueue := []string{}

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 1)

		installQueue = append(installQueue, goal.snaps[0].InstanceName)
		calledFlags = opts.Flags

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:           "install",
		IgnoreValidation: true,
		Snaps:            []string{"some-snap"},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	flags := snapstate.Flags{}
	flags.IgnoreValidation = true

	c.Check(calledFlags, check.DeepEquals, flags)
	c.Check(err, check.IsNil)
	c.Check(installQueue, check.DeepEquals, []string{"some-snap"})
	c.Check(res.Summary, check.Equals, `Install "some-snap" snap`)
}

func (s *snapsSuite) TestInstallEmptyName(c *check.C) {
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		return nil, nil, errors.New("should not be called")
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action: "install",
		Snaps:  []string{""},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.ErrorMatches, "cannot install snap with empty name")
}

func (s *snapsSuite) TestInstallOnNonDevModeDistro(c *check.C) {
	s.testInstall(c, false, snapstate.Flags{}, snap.R(0))
}
func (s *snapsSuite) TestInstallOnDevModeDistro(c *check.C) {
	s.testInstall(c, true, snapstate.Flags{}, snap.R(0))
}
func (s *snapsSuite) TestInstallRevision(c *check.C) {
	s.testInstall(c, false, snapstate.Flags{}, snap.R(42))
}

func (s *snapsSuite) testInstall(c *check.C, forcedDevmode bool, flags snapstate.Flags, revision snap.Revision) {
	calledFlags := snapstate.Flags{}
	installQueue := []string{}
	restore := sandbox.MockForceDevMode(forcedDevmode)
	defer restore()

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 1)

		calledFlags = opts.Flags
		installQueue = append(installQueue, goal.snaps[0].InstanceName)
		c.Check(revision, check.Equals, goal.snaps[0].RevOpts.Revision)

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemonWithFakeSnapManager(c)

	var buf bytes.Buffer
	if revision.Unset() {
		buf.WriteString(`{"action": "install"}`)
	} else {
		fmt.Fprintf(&buf, `{"action": "install", "revision": %s}`, revision.String())
	}
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", &buf)
	c.Assert(err, check.IsNil)

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 1)

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Status(), check.Equals, state.DoneStatus)
	c.Check(calledFlags, check.Equals, flags)
	c.Check(err, check.IsNil)
	c.Check(installQueue, check.DeepEquals, []string{"some-snap"})
	c.Check(chg.Kind(), check.Equals, "install-snap")
	c.Check(chg.Summary(), check.Equals, `Install "some-snap" snap`)
}

func (s *snapsSuite) TestInstallUserAgentContextCreated(c *check.C) {
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		s.ctx = ctx
		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	s.daemonWithFakeSnapManager(c)

	var buf bytes.Buffer
	buf.WriteString(`{"action": "install"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", &buf)
	s.asRootAuth(req)
	c.Assert(err, check.IsNil)
	req.Header.Add("User-Agent", "some-agent/1.0")

	rec := httptest.NewRecorder()
	s.serveHTTP(c, rec, req)
	c.Assert(rec.Code, check.Equals, 202)
	c.Check(store.ClientUserAgent(s.ctx), check.Equals, "some-agent/1.0")
}

func (s *snapsSuite) TestInstallFails(c *check.C) {
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		t := st.NewTask("fake-install-snap-error", "Install task")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemonWithFakeSnapManager(c)
	buf := bytes.NewBufferString(`{"action": "install"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/hello-world", buf)
	c.Assert(err, check.IsNil)

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 1)

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Err(), check.ErrorMatches, `(?sm).*Install task \(fake-install-snap-error errored\)`)
}

func (s *snapsSuite) TestRefresh(c *check.C) {
	var calledFlags snapstate.Flags
	calledUserID := 0
	installQueue := []string{}
	assertstateCalledUserID := 0

	defer daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		goal := g.(*storeUpdateGoalRecorder)
		calledFlags = opts.Flags
		calledUserID = opts.UserID
		installQueue = append(installQueue, goal.snaps[0].InstanceName)

		t := st.NewTask("fake-refresh-snap", "Doing a fake refresh")
		return state.NewTaskSet(t), nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		assertstateCalledUserID = userID
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action: "refresh",
		Snaps:  []string{"some-snap"},
	}
	inst.SetUserID(17)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	c.Check(assertstateCalledUserID, check.Equals, 17)
	c.Check(calledFlags, check.DeepEquals, snapstate.Flags{
		Transaction: client.TransactionPerSnap,
	})
	c.Check(calledUserID, check.Equals, 17)
	c.Check(err, check.IsNil)
	c.Check(installQueue, check.DeepEquals, []string{"some-snap"})
	c.Check(res.Summary, check.Equals, `Refresh "some-snap" snap`)
}

func (s *snapsSuite) TestRefreshDevMode(c *check.C) {
	var calledFlags snapstate.Flags
	calledUserID := 0
	installQueue := []string{}

	defer daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		goal := g.(*storeUpdateGoalRecorder)
		calledFlags = opts.Flags
		calledUserID = opts.UserID
		installQueue = append(installQueue, goal.snaps[0].InstanceName)

		t := st.NewTask("fake-refresh-snap", "Doing a fake install")
		return state.NewTaskSet(t), nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:  "refresh",
		DevMode: true,
		Snaps:   []string{"some-snap"},
	}
	inst.SetUserID(17)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	flags := snapstate.Flags{
		DevMode:     true,
		Transaction: client.TransactionPerSnap,
	}
	c.Check(calledFlags, check.DeepEquals, flags)
	c.Check(calledUserID, check.Equals, 17)
	c.Check(err, check.IsNil)
	c.Check(installQueue, check.DeepEquals, []string{"some-snap"})
	c.Check(res.Summary, check.Equals, `Refresh "some-snap" snap`)
}

func (s *snapsSuite) TestRefreshClassic(c *check.C) {
	var calledFlags snapstate.Flags

	defer daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		calledFlags = opts.Flags
		return nil, nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:  "refresh",
		Classic: true,
		Snaps:   []string{"some-snap"},
	}
	inst.SetUserID(17)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	_, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	c.Check(calledFlags, check.DeepEquals, snapstate.Flags{
		Classic:     true,
		Transaction: client.TransactionPerSnap,
	})
}

func (s *snapsSuite) TestRefreshIgnoreValidation(c *check.C) {
	var calledFlags snapstate.Flags
	calledUserID := 0
	installQueue := []string{}

	defer daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		goal := g.(*storeUpdateGoalRecorder)
		calledFlags = opts.Flags
		calledUserID = opts.UserID
		installQueue = append(installQueue, goal.snaps[0].InstanceName)

		t := st.NewTask("fake-refresh-snap", "Doing a fake install")
		return state.NewTaskSet(t), nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:           "refresh",
		IgnoreValidation: true,
		Snaps:            []string{"some-snap"},
	}
	inst.SetUserID(17)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	flags := snapstate.Flags{
		IgnoreValidation: true,
		Transaction:      client.TransactionPerSnap,
	}

	c.Check(calledFlags, check.DeepEquals, flags)
	c.Check(calledUserID, check.Equals, 17)
	c.Check(err, check.IsNil)
	c.Check(installQueue, check.DeepEquals, []string{"some-snap"})
	c.Check(res.Summary, check.Equals, `Refresh "some-snap" snap`)
}

func (s *snapsSuite) TestRefreshIgnoreRunning(c *check.C) {
	var calledFlags snapstate.Flags
	installQueue := []string{}

	defer daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		goal := g.(*storeUpdateGoalRecorder)
		calledFlags = opts.Flags
		installQueue = append(installQueue, goal.snaps[0].InstanceName)

		t := st.NewTask("fake-refresh-snap", "Doing a fake install")
		return state.NewTaskSet(t), nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action:        "refresh",
		IgnoreRunning: true,
		Snaps:         []string{"some-snap"},
	}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	flags := snapstate.Flags{
		IgnoreRunning: true,
		Transaction:   client.TransactionPerSnap,
	}

	c.Check(calledFlags, check.DeepEquals, flags)
	c.Check(err, check.IsNil)
	c.Check(installQueue, check.DeepEquals, []string{"some-snap"})
	c.Check(res.Summary, check.Equals, `Refresh "some-snap" snap`)
}

func (s *snapsSuite) TestRefreshCohort(c *check.C) {
	cohort := ""

	defer daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		goal := g.(*storeUpdateGoalRecorder)
		cohort = goal.snaps[0].RevOpts.CohortKey

		t := st.NewTask("fake-refresh-snap", "Doing a fake install")
		return state.NewTaskSet(t), nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action: "refresh",
		Snaps:  []string{"some-snap"},
	}
	inst.CohortKey = "xyzzy"

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	c.Check(cohort, check.Equals, "xyzzy")
	c.Check(res.Summary, check.Equals, `Refresh "some-snap" snap from "xyzzy" cohort`)
}

func (s *snapsSuite) TestRefreshLeaveCohort(c *check.C) {
	var leave *bool

	defer daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		goal := g.(*storeUpdateGoalRecorder)
		leave = &goal.snaps[0].RevOpts.LeaveCohort

		t := st.NewTask("fake-refresh-snap", "Doing a fake install")
		return state.NewTaskSet(t), nil
	})()
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{
		Action: "refresh",
		Snaps:  []string{"some-snap"},
	}
	inst.LeaveCohort = true

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)

	c.Check(*leave, check.Equals, true)
	c.Check(res.Summary, check.Equals, `Refresh "some-snap" snap`)
}

func (s *snapsSuite) TestSwitchInstruction(c *check.C) {
	var cohort, channel string
	var leave *bool

	defer daemon.MockSnapstateSwitch(func(s *state.State, name string, opts *snapstate.RevisionOptions, _ snapstate.PrereqTracker) (*state.TaskSet, error) {
		cohort = opts.CohortKey
		leave = &opts.LeaveCohort
		channel = opts.Channel

		t := s.NewTask("fake-switch", "Doing a fake switch")
		return state.NewTaskSet(t), nil
	})()

	d := s.daemon(c)
	st := d.Overlord().State()

	type T struct {
		channel string
		cohort  string
		leave   bool
		summary string
	}
	table := []T{
		{"", "some-cohort", false, `Switch "some-snap" snap to cohort "…me-cohort"`},
		{"some-channel", "", false, `Switch "some-snap" snap to channel "some-channel"`},
		{"some-channel", "some-cohort", false, `Switch "some-snap" snap to channel "some-channel" and cohort "…me-cohort"`},
		{"", "", true, `Switch "some-snap" snap away from cohort`},
		{"some-channel", "", true, `Switch "some-snap" snap to channel "some-channel" and away from cohort`},
	}

	for _, t := range table {
		cohort, channel = "", ""
		leave = nil
		inst := &daemon.SnapInstruction{
			Action: "switch",
			Snaps:  []string{"some-snap"},
		}
		inst.CohortKey = t.cohort
		inst.LeaveCohort = t.leave
		inst.Channel = t.channel

		st.Lock()
		res, err := inst.Dispatch()(context.Background(), inst, st)
		st.Unlock()
		c.Check(err, check.IsNil)

		c.Check(cohort, check.Equals, t.cohort)
		c.Check(channel, check.Equals, t.channel)
		c.Check(res.Summary, check.Equals, t.summary)
		c.Check(*leave, check.Equals, t.leave)
	}
}

func (s *snapsSuite) testRevertSnap(inst *daemon.SnapInstruction, c *check.C) {
	queue := []string{}

	instFlags, err := inst.ModeFlags()
	c.Assert(err, check.IsNil)

	defer daemon.MockSnapstateRevert(func(s *state.State, name string, flags snapstate.Flags, fromChange string) (*state.TaskSet, error) {
		c.Check(flags, check.Equals, instFlags)
		queue = append(queue, name)
		return nil, nil
	})()
	defer daemon.MockSnapstateRevertToRevision(func(s *state.State, name string, rev snap.Revision, flags snapstate.Flags, fromChange string) (*state.TaskSet, error) {
		c.Check(flags, check.Equals, instFlags)
		queue = append(queue, fmt.Sprintf("%s (%s)", name, rev))
		return nil, nil
	})()

	d := s.daemon(c)
	inst.Action = "revert"
	inst.Snaps = []string{"some-snap"}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	res, err := inst.Dispatch()(context.Background(), inst, st)
	c.Check(err, check.IsNil)
	if inst.Revision.Unset() {
		c.Check(queue, check.DeepEquals, []string{inst.Snaps[0]})
	} else {
		c.Check(queue, check.DeepEquals, []string{fmt.Sprintf("%s (%s)", inst.Snaps[0], inst.Revision)})
	}
	c.Check(res.Summary, check.Equals, `Revert "some-snap" snap`)
}

func (s *snapsSuite) TestRevertSnap(c *check.C) {
	s.testRevertSnap(&daemon.SnapInstruction{}, c)
}

func (s *snapsSuite) TestRevertSnapDevMode(c *check.C) {
	s.testRevertSnap(&daemon.SnapInstruction{DevMode: true}, c)
}

func (s *snapsSuite) TestRevertSnapJailMode(c *check.C) {
	s.testRevertSnap(&daemon.SnapInstruction{JailMode: true}, c)
}

func (s *snapsSuite) TestRevertSnapClassic(c *check.C) {
	s.testRevertSnap(&daemon.SnapInstruction{Classic: true}, c)
}

func (s *snapsSuite) TestRevertSnapToRevision(c *check.C) {
	inst := &daemon.SnapInstruction{}
	inst.Revision = snap.R(1)
	s.testRevertSnap(inst, c)
}

func (s *snapsSuite) TestRevertSnapToRevisionDevMode(c *check.C) {
	inst := &daemon.SnapInstruction{}
	inst.Revision = snap.R(1)
	inst.DevMode = true
	s.testRevertSnap(inst, c)
}

func (s *snapsSuite) TestRevertSnapToRevisionJailMode(c *check.C) {
	inst := &daemon.SnapInstruction{}
	inst.Revision = snap.R(1)
	inst.JailMode = true
	s.testRevertSnap(inst, c)
}

func (s *snapsSuite) TestRevertSnapToRevisionClassic(c *check.C) {
	inst := &daemon.SnapInstruction{}
	inst.Revision = snap.R(1)
	inst.Classic = true
	s.testRevertSnap(inst, c)
}

func (s *snapsSuite) TestErrToResponseNoSnapsDoesNotPanic(c *check.C) {
	si := &daemon.SnapInstruction{Action: "frobble"}
	errors := []error{
		store.ErrSnapNotFound,
		&store.RevisionNotAvailableError{},
		store.ErrNoUpdateAvailable,
		store.ErrLocalSnap,
		&snap.AlreadyInstalledError{Snap: "foo"},
		&snap.NotInstalledError{Snap: "foo"},
		&snapstate.SnapNeedsDevModeError{Snap: "foo"},
		&snapstate.SnapNeedsClassicError{Snap: "foo"},
		&snapstate.SnapNeedsClassicSystemError{Snap: "foo"},
		fakeNetError{message: "other"},
		fakeNetError{message: "timeout", timeout: true},
		fakeNetError{message: "temp", temporary: true},
		errors.New("some other error"),
	}

	for _, err := range errors {
		rspe := si.ErrToResponse(err)
		com := check.Commentf("%v", err)
		c.Assert(rspe, check.NotNil, com)
		status := rspe.Status
		c.Check(status/100 == 4 || status/100 == 5, check.Equals, true, com)
	}
}

func (s *snapsSuite) TestErrToResponseForRevisionNotAvailable(c *check.C) {
	si := &daemon.SnapInstruction{Action: "frobble", Snaps: []string{"foo"}}

	thisArch := arch.DpkgArchitecture()

	err := &store.RevisionNotAvailableError{
		Action:  "install",
		Channel: "stable",
		Releases: []channel.Channel{
			snaptest.MustParseChannel("beta", thisArch),
		},
	}
	rspe := si.ErrToResponse(err)
	c.Check(rspe, check.DeepEquals, &daemon.APIError{
		Status:  404,
		Message: "no snap revision on specified channel",
		Kind:    client.ErrorKindSnapChannelNotAvailable,
		Value: map[string]any{
			"snap-name":    "foo",
			"action":       "install",
			"channel":      "stable",
			"architecture": thisArch,
			"releases": []map[string]any{
				{"architecture": thisArch, "channel": "beta"},
			},
		},
	})

	err = &store.RevisionNotAvailableError{
		Action:  "install",
		Channel: "stable",
		Releases: []channel.Channel{
			snaptest.MustParseChannel("beta", "other-arch"),
		},
	}
	rspe = si.ErrToResponse(err)
	c.Check(rspe, check.DeepEquals, &daemon.APIError{
		Status:  404,
		Message: "no snap revision on specified architecture",
		Kind:    client.ErrorKindSnapArchitectureNotAvailable,
		Value: map[string]any{
			"snap-name":    "foo",
			"action":       "install",
			"channel":      "stable",
			"architecture": thisArch,
			"releases": []map[string]any{
				{"architecture": "other-arch", "channel": "beta"},
			},
		},
	})

	err = &store.RevisionNotAvailableError{}
	rspe = si.ErrToResponse(err)
	c.Check(rspe, check.DeepEquals, &daemon.APIError{
		Status:  404,
		Message: "no snap revision available as specified",
		Kind:    client.ErrorKindSnapRevisionNotAvailable,
		Value:   "foo",
	})
}

func (s *snapsSuite) TestErrToResponseForChangeConflict(c *check.C) {
	si := &daemon.SnapInstruction{Action: "frobble", Snaps: []string{"foo"}}

	err := &snapstate.ChangeConflictError{Snap: "foo", ChangeKind: "install"}
	rspe := si.ErrToResponse(err)
	c.Check(rspe, check.DeepEquals, &daemon.APIError{
		Status:  409,
		Message: `snap "foo" has "install" change in progress`,
		Kind:    client.ErrorKindSnapChangeConflict,
		Value: map[string]any{
			"snap-name":   "foo",
			"change-kind": "install",
		},
	})

	// only snap
	err = &snapstate.ChangeConflictError{Snap: "foo"}
	rspe = si.ErrToResponse(err)
	c.Check(rspe, check.DeepEquals, &daemon.APIError{
		Status:  409,
		Message: `snap "foo" has changes in progress`,
		Kind:    client.ErrorKindSnapChangeConflict,
		Value: map[string]any{
			"snap-name": "foo",
		},
	})

	// only kind
	err = &snapstate.ChangeConflictError{Message: "specific error msg", ChangeKind: "some-global-op"}
	rspe = si.ErrToResponse(err)
	c.Check(rspe, check.DeepEquals, &daemon.APIError{
		Status:  409,
		Message: "specific error msg",
		Kind:    client.ErrorKindSnapChangeConflict,
		Value: map[string]any{
			"change-kind": "some-global-op",
		},
	})
}

func (s *snapsSuite) TestPostSnapInvalidTransaction(c *check.C) {
	s.daemonWithOverlordMock()

	for _, action := range []string{"remove", "revert", "enable", "disable", "xyzzy"} {
		expectedErr := fmt.Sprintf(`transaction type is unsupported for "%s" actions`, action)
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "transaction": "per-snap"}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, action != "xyzzy")
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestPostSnapWrongTransaction(c *check.C) {
	s.daemonWithOverlordMock()
	const expectedErr = "invalid value for transaction type: xyz"

	for _, action := range []string{"install", "refresh"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": "%s", "transaction": "xyz"}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400, check.Commentf("%q", action))
		c.Check(rspe.Message, check.Equals, expectedErr, check.Commentf("%q", action))
	}
}

func (s *snapsSuite) TestRefreshEnforce(c *check.C) {
	installValset := assertstest.FakeAssertion(map[string]any{
		"type":         "validation-set",
		"authority-id": "foo",
		"series":       "16",
		"account-id":   "foo",
		"name":         "baz",
		"sequence":     "3",
		"snaps": []any{
			map[string]any{
				"name":     "install-snap",
				"id":       "mysnapdddddddddddddddddddddddddd",
				"presence": "required",
			},
		},
	}).(*asserts.ValidationSet)
	updateValset := assertstest.FakeAssertion(map[string]any{
		"type":         "validation-set",
		"authority-id": "foo",
		"series":       "16",
		"account-id":   "foo",
		"name":         "bar",
		"sequence":     "2",
		"snaps": []any{
			map[string]any{
				"name":     "update-snap",
				"id":       "mysnapcccccccccccccccccccccccccc",
				"presence": "required",
			},
		},
	}).(*asserts.ValidationSet)

	restore := daemon.MockAssertstateTryEnforceValidationSets(func(st *state.State, validationSets []string, userID int, snaps []*snapasserts.InstalledSnap, ignoreValidation map[string]bool) error {
		return &snapasserts.ValidationSetsValidationError{
			WrongRevisionSnaps: map[string]map[snap.Revision][]string{
				"update-snap": {snap.R(2): []string{"foo/baz"}},
			},
			MissingSnaps: map[string]map[snap.Revision][]string{
				"install-snap": {snap.R(1): []string{"foo/bar=2"}},
			},
			Sets: map[string]*asserts.ValidationSet{"foo/baz": installValset, "foo/bar": updateValset},
		}
	})
	defer restore()

	restore = daemon.MockSnapstateResolveValSetEnforcementError(func(_ context.Context, st *state.State, validErr *snapasserts.ValidationSetsValidationError, pinnedSeqs map[string]int, _ int) ([]*state.TaskSet, []string, error) {
		c.Assert(pinnedSeqs, check.DeepEquals, map[string]int{"foo/bar": 2})
		c.Assert(validErr, check.Not(check.IsNil))

		t := st.NewTask("fake-enforce-snaps", "...")
		return []*state.TaskSet{state.NewTaskSet(t)}, []string{"install-snap", "update-snap"}, nil
	})
	defer restore()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "refresh", ValidationSets: []string{"foo/bar=2", "foo/baz"}}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Enforce validation sets "foo/bar=2", "foo/baz" for snaps "install-snap", "update-snap"`)
	c.Check(res.Affected, check.DeepEquals, []string{"install-snap", "update-snap"})
}

func (s *snapsSuite) TestRefreshEnforceWithPreexistingSet(c *check.C) {
	unpinned := assertstest.FakeAssertion(map[string]any{
		"type":         "validation-set",
		"authority-id": "foo",
		"series":       "16",
		"account-id":   "foo",
		"name":         "preexisting-unpinned",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "install-snap",
				"id":       "mysnapdddddddddddddddddddddddddd",
				"presence": "required",
			},
		},
	}).(*asserts.ValidationSet)

	pinned := assertstest.FakeAssertion(map[string]any{
		"type":         "validation-set",
		"authority-id": "foo",
		"series":       "16",
		"account-id":   "foo",
		"name":         "preexisting-pinned",
		"sequence":     "3",
		"snaps": []any{
			map[string]any{
				"name":     "install-snap",
				"id":       "mysnapdddddddddddddddddddddddddd",
				"presence": "required",
			},
		},
	}).(*asserts.ValidationSet)

	d := s.daemon(c)
	st := d.Overlord().State()

	// start tracking these already, the pinned one should end up still pinned
	// after everything is done
	st.Lock()
	assertstate.UpdateValidationSet(st, &assertstate.ValidationSetTracking{
		AccountID: "foo",
		Mode:      assertstate.Enforce,
		Name:      "preexisting-pinned",
		PinnedAt:  3,
		Current:   3,
	})
	assertstate.UpdateValidationSet(st, &assertstate.ValidationSetTracking{
		AccountID: "foo",
		Mode:      assertstate.Enforce,
		Name:      "preexisting-unpinned",
		Current:   1,
	})
	st.Unlock()

	vset := assertstest.FakeAssertion(map[string]any{
		"type":         "validation-set",
		"authority-id": "foo",
		"series":       "16",
		"account-id":   "foo",
		"name":         "new",
		"sequence":     "2",
		"snaps": []any{
			map[string]any{
				"name":     "install-snap",
				"id":       "mysnapcccccccccccccccccccccccccc",
				"presence": "required",
			},
		},
	}).(*asserts.ValidationSet)

	restore := daemon.MockAssertstateTryEnforceValidationSets(func(st *state.State, validationSets []string, userID int, snaps []*snapasserts.InstalledSnap, ignoreValidation map[string]bool) error {
		return &snapasserts.ValidationSetsValidationError{
			MissingSnaps: map[string]map[snap.Revision][]string{
				"install-snap": {snap.R(1): []string{"foo/new=2"}},
			},
			Sets: map[string]*asserts.ValidationSet{
				"foo/preexisting-unpinned": unpinned,
				"foo/preexisting-pinned":   pinned,
				"foo/new":                  vset,
			},
		}
	})
	defer restore()

	restore = daemon.MockSnapstateResolveValSetEnforcementError(func(_ context.Context, st *state.State, validErr *snapasserts.ValidationSetsValidationError, pinnedSeqs map[string]int, _ int) ([]*state.TaskSet, []string, error) {
		// note that the unpinned set is not present here
		c.Assert(pinnedSeqs, check.DeepEquals, map[string]int{
			"foo/new":                2,
			"foo/preexisting-pinned": 3,
		})
		c.Assert(validErr, check.Not(check.IsNil))

		t := st.NewTask("fake-enforce-snaps", "...")
		return []*state.TaskSet{state.NewTaskSet(t)}, []string{"install-snap"}, nil
	})
	defer restore()

	inst := &daemon.SnapInstruction{Action: "refresh", ValidationSets: []string{"foo/new=2"}}

	st.Lock()
	defer st.Unlock()

	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.IsNil)
	c.Check(res.Summary, check.Equals, `Enforce validation sets "foo/new=2" for snaps "install-snap"`)
	c.Check(res.Affected, check.DeepEquals, []string{"install-snap"})
}

func (s *snapsSuite) TestRefreshEnforceTryEnforceValidationSetsError(c *check.C) {
	var refreshSnapAssertions int
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions++
		c.Check(opts, check.IsNil)
		return nil
	})()

	tryEnforceErr := fmt.Errorf("boom")
	defer daemon.MockAssertstateTryEnforceValidationSets(func(st *state.State, validationSets []string, userID int, snaps []*snapasserts.InstalledSnap, ignoreValidation map[string]bool) error {
		return tryEnforceErr
	})()

	var snapstateEnforceSnaps int
	defer daemon.MockSnapstateResolveValSetEnforcementError(func(_ context.Context, _ *state.State, validErr *snapasserts.ValidationSetsValidationError, _ map[string]int, _ int) ([]*state.TaskSet, []string, error) {
		snapstateEnforceSnaps++
		c.Check(validErr, check.NotNil)
		return nil, nil, nil
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "refresh", ValidationSets: []string{"foo/baz"}}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	_, err := inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.ErrorMatches, `boom`)
	c.Check(refreshSnapAssertions, check.Equals, 1)
	c.Check(snapstateEnforceSnaps, check.Equals, 0)

	// ValidationSetsValidationError is expected and fine
	tryEnforceErr = &snapasserts.ValidationSetsValidationError{}

	_, err = inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.IsNil)
	c.Check(refreshSnapAssertions, check.Equals, 2)
	c.Check(snapstateEnforceSnaps, check.Equals, 1)
}

func (s *snapsSuite) TestRefreshEnforceWithSnapsIsAnError(c *check.C) {
	var refreshSnapAssertions bool
	defer daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		refreshSnapAssertions = true
		c.Check(opts, check.IsNil)
		return fmt.Errorf("unexptected")
	})()

	var tryEnforceValidationSets bool
	defer daemon.MockAssertstateTryEnforceValidationSets(func(st *state.State, validationSets []string, userID int, snaps []*snapasserts.InstalledSnap, ignoreValidation map[string]bool) error {
		tryEnforceValidationSets = true
		return fmt.Errorf("unexpected")
	})()

	var snapstateEnforceSnaps bool
	defer daemon.MockSnapstateResolveValSetEnforcementError(func(context.Context, *state.State, *snapasserts.ValidationSetsValidationError, map[string]int, int) ([]*state.TaskSet, []string, error) {
		snapstateEnforceSnaps = true
		return nil, nil, fmt.Errorf("unexpected")
	})()

	d := s.daemon(c)
	inst := &daemon.SnapInstruction{Action: "refresh", Snaps: []string{"some-snap"}, ValidationSets: []string{"foo/baz"}}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	_, err := inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.ErrorMatches, `snap names cannot be specified with validation sets to enforce`)
	c.Check(refreshSnapAssertions, check.Equals, false)
	c.Check(tryEnforceValidationSets, check.Equals, false)
	c.Check(snapstateEnforceSnaps, check.Equals, false)
}

func (s *snapsSuite) TestRefreshEnforceSetsNoUnmetConstraints(c *check.C) {
	restore := daemon.MockAssertstateTryEnforceValidationSets(func(st *state.State, validationSets []string, userID int, snaps []*snapasserts.InstalledSnap, ignoreValidation map[string]bool) error {
		return nil
	})
	defer restore()

	restore = daemon.MockSnapstateResolveValSetEnforcementError(func(context.Context, *state.State, *snapasserts.ValidationSetsValidationError, map[string]int, int) ([]*state.TaskSet, []string, error) {
		err := errors.New("unexpected call to snapstate.EnforceSnaps")
		c.Error(err)
		return nil, nil, err
	})
	defer restore()

	d := s.daemon(c)
	valsets := []string{"foo/baz", "foo/bar"}
	inst := &daemon.SnapInstruction{Action: "refresh", ValidationSets: valsets}

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	resp, err := inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.IsNil)
	c.Check(resp.Affected, check.IsNil)
	c.Check(resp.Tasksets, check.IsNil)
	c.Check(resp.Summary, check.Equals, fmt.Sprintf("Enforce validation sets %s", strutil.Quoted(valsets)))
}

func (s *snapsSuite) TestRefreshEnforceResolveErrorChangeConflictError(c *check.C) {
	restore := daemon.MockAssertstateTryEnforceValidationSets(func(st *state.State, validationSets []string, userID int, snaps []*snapasserts.InstalledSnap, ignoreValidation map[string]bool) error {
		return &snapasserts.ValidationSetsValidationError{}
	})
	defer restore()

	restore = daemon.MockSnapstateResolveValSetEnforcementError(func(_ context.Context, st *state.State, validErr *snapasserts.ValidationSetsValidationError, pinnedSeqs map[string]int, _ int) ([]*state.TaskSet, []string, error) {
		return nil, nil, fmt.Errorf("wrapped error: %w", &snapstate.ChangeConflictError{
			Snap:       "some-snap",
			ChangeID:   "12",
			ChangeKind: "a-thing",
			Message:    "conflict with a thing",
		})
	})
	defer restore()

	s.daemon(c)

	buf := strings.NewReader(`{"action": "refresh", "validation-sets": ["foo/bar"]}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 409)
	c.Check(rspe.Kind, check.Equals, client.ErrorKindSnapChangeConflict)
	c.Check(rspe.Message, check.Equals, "conflict with a thing")
}

func (s *snapsSuite) TestHoldAllRefreshes(c *check.C) {
	d := s.daemon(c)
	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	for _, time := range []string{"forever", "0001-02-03T00:00:00Z"} {
		called := false
		restore := daemon.MockConfigstateConfigureInstalled(func(s *state.State, name string, patchValues map[string]any, flags int) (*state.TaskSet, error) {
			called = true
			c.Assert(patchValues, check.DeepEquals, map[string]any{"refresh.hold": time})
			c.Assert(name, check.Equals, "core")
			return state.NewTaskSet(s.NewTask("fake-task", "Fakeness")), nil
		})

		inst := &daemon.SnapInstruction{
			Action:    "hold",
			Time:      time,
			HoldLevel: "auto-refresh",
		}

		res, err := inst.DispatchForMany()(context.Background(), inst, st)
		c.Assert(err, check.IsNil)
		c.Assert(res.Tasksets, check.Not(check.IsNil))
		c.Assert(res.Affected, check.IsNil)
		c.Assert(res.Summary, check.Equals, `Hold auto-refreshes for all snaps`)
		c.Assert(called, check.Equals, true)
		restore()
	}
}

func (s *snapsSuite) TestHoldManyRefreshes(c *check.C) {
	snaps := []string{"some-snap", "other-snap"}
	d := s.daemon(c)
	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	for _, time := range []string{"forever", "0001-02-03T00:00:00Z"} {
		called := false
		restore := daemon.MockSnapstateHoldRefreshesBySystem(func(s *state.State, level snapstate.HoldLevel, mockTime string, mockSnaps []string) error {
			called = true
			c.Assert(level, check.Equals, snapstate.HoldAutoRefresh)
			c.Assert(mockTime, check.Equals, time)
			c.Assert(mockSnaps, check.DeepEquals, snaps)
			return nil
		})

		inst := &daemon.SnapInstruction{
			Action:    "hold",
			Snaps:     snaps,
			Time:      time,
			HoldLevel: "auto-refresh",
		}

		res, err := inst.DispatchForMany()(context.Background(), inst, st)
		c.Assert(err, check.IsNil)
		c.Assert(res.Tasksets, check.IsNil)
		c.Assert(res.Affected, check.DeepEquals, snaps)
		c.Assert(res.Summary, check.Equals, fmt.Sprintf(`Hold auto-refreshes for %s`, strutil.Quoted(snaps)))
		c.Assert(called, check.Equals, true)
		restore()
	}
}

func (s *snapsSuite) TestHoldRefresh(c *check.C) {
	d := s.daemon(c)
	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	for _, time := range []string{"forever", "0001-02-03T00:00:00Z"} {
		called := false
		restore := daemon.MockSnapstateHoldRefreshesBySystem(func(s *state.State, level snapstate.HoldLevel, mockTime string, mockSnaps []string) error {
			called = true
			c.Assert(level, check.Equals, snapstate.HoldGeneral)
			c.Assert(mockTime, check.Equals, time)
			c.Assert(mockSnaps, check.DeepEquals, []string{"some-snap"})
			return nil
		})

		inst := &daemon.SnapInstruction{
			Action:    "hold",
			Snaps:     []string{"some-snap"},
			Time:      time,
			HoldLevel: "general",
		}

		res, err := inst.Dispatch()(context.Background(), inst, st)
		c.Assert(err, check.IsNil)
		c.Assert(res.Tasksets, check.IsNil)
		c.Assert(res.Summary, check.Equals, `Hold general refreshes for "some-snap"`)
		c.Assert(called, check.Equals, true)
		restore()
	}
}

func (s *snapsSuite) TestUnholdAllRefreshes(c *check.C) {
	restore := daemon.MockConfigstateConfigureInstalled(func(s *state.State, name string, patchValues map[string]any, flags int) (*state.TaskSet, error) {
		c.Assert(patchValues, check.DeepEquals, map[string]any{"refresh.hold": nil})
		c.Assert(name, check.Equals, "core")
		return state.NewTaskSet(s.NewTask("fake-task", "Fakeness")), nil
	})
	defer restore()

	d := s.daemon(c)
	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	inst := &daemon.SnapInstruction{
		Action: "unhold",
	}

	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.IsNil)
	c.Assert(res.Tasksets, check.Not(check.IsNil))
	c.Assert(res.Affected, check.IsNil)
	c.Assert(res.Summary, check.Equals, `Remove auto-refresh hold on all snaps`)
}

func (s *snapsSuite) TestUnholdManyRefreshes(c *check.C) {
	snaps := []string{"some-snap", "other-snap"}

	restore := daemon.MockSnapstateProceedWithRefresh(func(s *state.State, gatingSnap string, mockSnaps []string) error {
		c.Assert(mockSnaps, check.DeepEquals, snaps)
		c.Assert(gatingSnap, check.Equals, "system")
		return nil
	})
	defer restore()

	d := s.daemon(c)
	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	inst := &daemon.SnapInstruction{
		Action: "unhold",
		Snaps:  snaps,
	}

	res, err := inst.DispatchForMany()(context.Background(), inst, st)
	c.Assert(err, check.IsNil)
	c.Assert(res.Tasksets, check.IsNil)
	c.Assert(res.Affected, check.DeepEquals, snaps)
	c.Assert(res.Summary, check.Equals, fmt.Sprintf(`Remove refresh hold on %s`, strutil.Quoted(inst.Snaps)))
}

func (s *snapsSuite) TestUnholdRefresh(c *check.C) {
	restore := daemon.MockSnapstateProceedWithRefresh(func(s *state.State, gatingSnap string, mockSnaps []string) error {
		c.Assert(mockSnaps, check.DeepEquals, []string{"some-snap"})
		c.Assert(gatingSnap, check.Equals, "system")
		return nil
	})
	defer restore()

	inst := &daemon.SnapInstruction{
		Action: "unhold",
		Snaps:  []string{"some-snap"},
	}

	d := s.daemon(c)
	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	res, err := inst.Dispatch()(context.Background(), inst, st)

	c.Assert(err, check.IsNil)
	c.Assert(res.Tasksets, check.IsNil)
	c.Assert(res.Summary, check.Equals, `Remove refresh hold on "some-snap"`)
}

func (s *snapsSuite) TestUnholEndpoint(c *check.C) {
	restoreProceedWithRefresh := daemon.MockSnapstateProceedWithRefresh(func(s *state.State, gatingSnap string, mockSnaps []string) error {
		c.Assert(mockSnaps, check.DeepEquals, []string{"some-snap"})
		c.Assert(gatingSnap, check.Equals, "system")
		return nil
	})
	defer restoreProceedWithRefresh()

	soon := 0
	_, restoreEnsureStateSoon := daemon.MockEnsureStateSoon(func(s *state.State) {
		soon++
	})
	defer restoreEnsureStateSoon()

	s.daemon(c)

	buf := bytes.NewBufferString(`{"action": "unhold"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.jsonReq(c, req, nil, actionIsExpected)
	c.Assert(err, check.IsNil)
	c.Assert(soon, check.Equals, 1)
	c.Assert(rspe.Status, check.Equals, 202)
}

func (s *snapsSuite) TestHoldWithInvalidTime(c *check.C) {
	s.daemon(c)
	for _, snaps := range [][]string{{}, {"some-snap"}, {"some-snap", "other-snap"}} {
		buf := bytes.NewBufferString(fmt.Sprintf(`{"action": "hold", "snaps": [%s], "time": "boom"}`, strutil.Quoted(snaps)))
		req, err := http.NewRequest("POST", "/v2/snaps", buf)
		req.Header.Set("Content-Type", "application/json")
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400)
		c.Assert(rspe.Error(), check.Matches, `hold action requires time to be "forever" or in RFC3339 format: parsing time "boom".*`)
	}
}

func (s *snapsSuite) TestHoldWithInvalidTimeSingleSnap(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "hold", "time": "boom"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `hold action requires time to be "forever" or in RFC3339 format: parsing time "boom".*`)
}

func (s *snapsSuite) TestHoldWithInvalidHoldLevel(c *check.C) {
	s.daemon(c)
	for _, snaps := range [][]string{{}, {"some-snap"}, {"some-snap", "other-snap"}} {
		buf := bytes.NewBufferString(fmt.Sprintf(`{"action": "hold", "snaps": [%s], "time": "forever", "hold-level": "boom"}`, strutil.Quoted(snaps)))
		req, err := http.NewRequest("POST", "/v2/snaps", buf)
		req.Header.Set("Content-Type", "application/json")
		c.Assert(err, check.IsNil)

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400)
		c.Assert(rspe.Error(), check.Matches, `hold action requires hold-level to be either "auto-refresh" or "general".*`)
	}
}

func (s *snapsSuite) TestHoldWithInvalidHoldLevelSingleSnap(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "hold", "time": "forever", "hold-level": "boom"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `hold action requires hold-level to be either "auto-refresh" or "general".*`)
}

func (s *snapsSuite) TestHoldMissingTime(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "hold"}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `hold action requires a non-empty time value.*`)
}

func (s *snapsSuite) TestHoldMissingTimeSingleSnap(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "hold"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `hold action requires a non-empty time value.*`)
}

func (s *snapsSuite) TestHoldMissingLevel(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "hold", "time": "forever"}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `hold action requires a non-empty hold-level value.*`)
}

func (s *snapsSuite) TestHoldMissingLevelSingleSnap(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "hold", "time": "forever"}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `hold action requires a non-empty hold-level value.*`)
}

func (s *snapsSuite) TestOnlyAllowTimeParamForHold(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "refresh", "time": "forever"}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `time can only be specified for the "hold" action.*`)
}

func (s *snapsSuite) TestOnlyAllowHoldLevelParamForHold(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "refresh", "hold-level": "auto-refresh"}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `hold-level can only be specified for the "hold" action.*`)
}

func (s *snapsSuite) TestHoldAllSnapsGeneralRefreshesNotSupported(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "hold", "time": "forever", "hold-level": "general"}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `cannot hold: holding general refreshes for all snaps is not supported.*`)
}

func (s *snapsSuite) TestOnlyAllowUnaliasedOrPrefer(c *check.C) {
	s.daemon(c)
	buf := bytes.NewBufferString(`{"action": "install", "unaliased": true, "prefer": true}`)
	req, err := http.NewRequest("POST", "/v2/snaps/foo", buf)
	req.Header.Set("Content-Type", "application/json")
	c.Assert(err, check.IsNil)

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Assert(rspe.Error(), check.Matches, `cannot use unaliased and prefer flags together.*`)
}

func (s *snapsSuite) TestPostRemoveComponents(c *check.C) {
	d := s.daemonWithOverlordMockAndStore()

	var t *state.Task
	defer daemon.MockSnapstateRemoveComponents(func(st *state.State, snapName string, compNames []string, opts snapstate.RemoveComponentsOpts) ([]*state.TaskSet, error) {
		c.Check(snapName, check.Equals, "foo")
		c.Check(compNames, check.DeepEquals, []string{"comp1", "comp2"})
		t = st.NewTask("fake-remove-comps-2", "Remove two")
		return []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	buf := strings.NewReader(`{"action": "remove","components":["comp1","comp2"]}`)
	req, err := http.NewRequest("POST", "/v2/snaps/foo", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	c.Assert(rsp.Status, check.Equals, 202)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	tasks := chg.Tasks()
	c.Check(len(tasks), check.Equals, 1)
	c.Check(tasks[0], check.DeepEquals, t)
	c.Check(chg.Summary(), check.Equals, `Remove component(s) [comp1 comp2] for "foo" snap`)

	var apiData map[string]any
	c.Check(chg.Get("api-data", &apiData), check.IsNil)
	c.Check(apiData["snap-names"], check.IsNil)
	c.Check(apiData["components"], check.DeepEquals,
		map[string]any{"foo": []any{"comp1", "comp2"}})
}

func (s *snapsSuite) TestPostComponentsWrongAction(c *check.C) {
	s.daemonWithOverlordMockAndStore()

	for _, action := range []string{"revert", "enable", "disable"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": %q,"components":["comp1","comp2"]}`,
			action))
		req, err := http.NewRequest("POST", "/v2/snaps/foo", buf)
		c.Assert(err, check.IsNil)
		req.Header.Set("Content-Type", "application/json")

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400)
		c.Check(rspe.Message, testutil.Contains,
			fmt.Sprintf(`%q action is not supported for components`, action))
	}
}

func (s *snapsSuite) TestPostComponentsRemoveMany(c *check.C) {
	d := s.daemonWithOverlordMockAndStore()

	var compTsk *state.Task
	numCalls := 0
	expectedMsg := "Remove component(s)"
	defer daemon.MockSnapstateRemoveComponents(func(st *state.State, snapName string, compNames []string, opts snapstate.RemoveComponentsOpts) ([]*state.TaskSet, error) {
		numCalls++
		if numCalls == 2 {
			expectedMsg += ","
		}
		switch snapName {
		case "snap1":
			c.Check(compNames, check.DeepEquals, []string{"comp1", "comp2"})
			expectedMsg += ` [comp1 comp2] for "snap1" snap`
		case "snap2":
			c.Check(compNames, check.DeepEquals, []string{"comp3", "comp4"})
			expectedMsg += ` [comp3 comp4] for "snap2" snap`
		default:
			c.Error("unexpected snap:", snapName)
		}
		compTsk = st.NewTask("fake-remove-comps-2", "Remove two")
		return []*state.TaskSet{state.NewTaskSet(compTsk)}, nil
	})()

	buf := strings.NewReader(`{"action": "remove", "components": { "snap1": ["comp1", "comp2"], "snap2": ["comp3", "comp4"] }}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, check.Equals, 202)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Check(chg.Summary(), check.Equals, expectedMsg)
	tasks := chg.Tasks()
	c.Check(len(tasks), check.Equals, 2)
	c.Check(numCalls, check.Equals, 2)

	var apiData map[string]any
	c.Check(chg.Get("api-data", &apiData), check.IsNil)
	c.Check(apiData["snap-names"], check.IsNil)
	c.Check(apiData["components"], check.DeepEquals,
		map[string]any{
			"snap1": []any{"comp1", "comp2"},
			"snap2": []any{"comp3", "comp4"}},
	)
}

func (s *snapsSuite) TestPostComponentsRemoveManyWithSnaps(c *check.C) {
	d := s.daemonWithOverlordMockAndStore()

	var snapTsk *state.Task
	defer daemon.MockSnapstateRemoveMany(func(s *state.State, names []string, opts *snapstate.RemoveFlags) ([]string, []*state.TaskSet, error) {
		c.Check(names, check.HasLen, 2)
		snapTsk = s.NewTask("fake-remove-2", "Remove two")
		return names, []*state.TaskSet{state.NewTaskSet(snapTsk)}, nil
	})()
	var compTsk *state.Task
	expectedMsg := `Remove snaps "foo", "bar" - Remove component(s)`
	numCalls := 0
	defer daemon.MockSnapstateRemoveComponents(func(st *state.State, snapName string, compNames []string, opts snapstate.RemoveComponentsOpts) ([]*state.TaskSet, error) {
		numCalls++
		if numCalls == 2 {
			expectedMsg += ","
		}
		switch snapName {
		case "snap1":
			c.Check(compNames, check.DeepEquals, []string{"comp1", "comp2"})
			expectedMsg += ` [comp1 comp2] for "snap1" snap`
		case "snap2":
			c.Check(compNames, check.DeepEquals, []string{"comp3", "comp4"})
			expectedMsg += ` [comp3 comp4] for "snap2" snap`
		default:
			c.Error("unexpected snap:", snapName)
		}
		compTsk = st.NewTask("fake-remove-comps-2", "Remove two")
		return []*state.TaskSet{state.NewTaskSet(compTsk)}, nil
	})()

	buf := strings.NewReader(`{"action": "remove", "snaps":["foo", "bar"], "components": { "snap1": ["comp1", "comp2"], "snap2": ["comp3", "comp4"] }}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.jsonReq(c, req, nil, actionIsExpected)
	c.Check(rsp.Status, check.Equals, 202)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()
	chg := st.Change(rsp.Change)
	c.Check(chg.Summary(), check.Equals, expectedMsg)
	tasks := chg.Tasks()
	c.Check(len(tasks), check.Equals, 3)
	c.Check(numCalls, check.Equals, 2)

	var apiData map[string]any
	c.Check(chg.Get("api-data", &apiData), check.IsNil)
	c.Check(apiData["snap-names"], check.DeepEquals, []any{"foo", "bar"})
	c.Check(apiData["components"], check.DeepEquals,
		map[string]any{
			"snap1": []any{"comp1", "comp2"},
			"snap2": []any{"comp3", "comp4"}},
	)
}

func (s *snapsSuite) TestPostComponentsManyWrongAction(c *check.C) {
	s.daemonWithOverlordMockAndStore()

	for _, action := range []string{"revert", "enable", "disable"} {
		buf := strings.NewReader(fmt.Sprintf(`{"action": %q, "snaps":["foo", "bar"], "components": { "snap1": ["comp1", "comp2"], "snap2": ["comp3", "comp4"] }}`, action))
		req, err := http.NewRequest("POST", "/v2/snaps", buf)
		c.Assert(err, check.IsNil)
		req.Header.Set("Content-Type", "application/json")

		rspe := s.errorReq(c, req, nil, actionIsExpected)
		c.Check(rspe.Status, check.Equals, 400)
		c.Check(rspe.Message, testutil.Contains,
			fmt.Sprintf(`%q action is not supported for components`, action))
	}
}

func (s *snapsSuite) TestPostComponentsManyRemoveCompsAndSnap(c *check.C) {
	s.daemonWithOverlordMockAndStore()

	buf := strings.NewReader(`{"action": "remove", "snaps":["snap1", "bar"], "components": { "snap1": ["comp1", "comp2"]}}`)
	req, err := http.NewRequest("POST", "/v2/snaps", buf)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rspe := s.errorReq(c, req, nil, actionIsExpected)
	c.Check(rspe.Status, check.Equals, 400)
	c.Check(rspe.Message, testutil.Contains,
		`cannot remove "snap1", "bar": unexpected request to remove some components and also the full snap (which would remove all components) for "snap1"`)
}

func (s *snapsSuite) TestInstallWithComponents(c *check.C) {
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 1)

		c.Check(goal.snaps[0].InstanceName, check.Equals, "some-snap")
		c.Check(goal.snaps[0].Components, check.DeepEquals, []string{"comp1", "comp2"})

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemonWithFakeSnapManager(c)

	r := strings.NewReader(`{"action": "install", "components": ["comp1", "comp2"]}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", r)
	c.Assert(err, check.IsNil)

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 1)

	var data map[string]any
	err = chg.Get("api-data", &data)
	c.Assert(err, check.IsNil)
	c.Check(data, check.DeepEquals, map[string]any{
		"snap-names": []any{"some-snap"},
		"components": map[string]any{
			"some-snap": []any{"comp1", "comp2"},
		},
	})

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Status(), check.Equals, state.DoneStatus)
	c.Check(err, check.IsNil)
	c.Check(chg.Kind(), check.Equals, "install-snap")
	c.Check(chg.Summary(), check.Equals, `Install "some-snap" snap with components "comp1", "comp2"`)
}

func (s *snapsSuite) TestUpdateWithAdditionalComponents(c *check.C) {
	restore := daemon.MockAssertstateRefreshSnapAssertions(func(s *state.State, userID int, opts *assertstate.RefreshAssertionsOptions) error {
		return nil
	})
	defer restore()

	restore = daemon.MockSnapstateUpdateOne(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) (*state.TaskSet, error) {
		goal := g.(*storeUpdateGoalRecorder)
		c.Check(goal.snaps, check.DeepEquals, []snapstate.StoreUpdate{{
			InstanceName:         "some-snap",
			AdditionalComponents: []string{"comp1", "comp2"},
		}})
		t := st.NewTask("fake-refresh-snap", "Doing a fake install")
		return state.NewTaskSet(t), nil
	})
	defer restore()

	d := s.daemonWithFakeSnapManager(c)

	r := strings.NewReader(`{"action": "refresh", "components": ["comp1", "comp2"]}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", r)
	c.Assert(err, check.IsNil)

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 1)

	var data map[string]any
	err = chg.Get("api-data", &data)
	c.Assert(err, check.IsNil)
	c.Check(data, check.DeepEquals, map[string]any{
		"snap-names": []any{"some-snap"},
		"components": map[string]any{
			"some-snap": []any{"comp1", "comp2"},
		},
	})

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Status(), check.Equals, state.DoneStatus)
	c.Check(err, check.IsNil)
	c.Check(chg.Kind(), check.Equals, "refresh-snap")
	c.Check(chg.Summary(), check.Equals, `Refresh "some-snap" snap with components "comp1", "comp2"`)
}

func (s *snapsSuite) TestInstallManyWithComponents(c *check.C) {
	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 2)

		c.Check(goal.snaps, check.DeepEquals, []snapstate.StoreSnap{
			{
				InstanceName: "some-snap",
				Components:   []string{"some-comp1", "some-comp2"},
			},
			{
				InstanceName: "other-snap",
				Components:   []string{"other-comp1"},
			},
		})

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return storeSnapInfos(goal.snaps), []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemonWithFakeSnapManager(c)

	r := strings.NewReader(`{"action": "install", "snaps": ["some-snap", "other-snap"], "components": {"some-snap": ["some-comp1", "some-comp2"], "other-snap": ["other-comp1"]}}`)
	req, err := http.NewRequest("POST", "/v2/snaps", r)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 1)

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Status(), check.Equals, state.DoneStatus)
	c.Check(err, check.IsNil)
	c.Check(chg.Kind(), check.Equals, "install-snap")
	c.Check(chg.Summary(), check.Equals, `Install snaps "some-snap" (with components "some-comp1", "some-comp2"), "other-snap" (with component "other-comp1")`)
}

func (s *snapsSuite) TestUpdateManyWithComponents(c *check.C) {
	restore := daemon.MockAssertstateRefreshSnapAssertions(func(*state.State, int, *assertstate.RefreshAssertionsOptions) error {
		return nil
	})
	defer restore()

	restore = daemon.MockSnapstateUpdateWithGoal(func(ctx context.Context, st *state.State, g snapstate.UpdateGoal, filter func(*snap.Info, *snapstate.SnapState) bool, opts snapstate.Options) ([]string, *snapstate.UpdateTaskSets, error) {
		goal := g.(*storeUpdateGoalRecorder)
		c.Assert(goal.snaps, check.HasLen, 2)

		c.Check(goal.snaps, check.DeepEquals, []snapstate.StoreUpdate{
			{
				InstanceName:         "some-snap",
				AdditionalComponents: []string{"some-comp1", "some-comp2"},
			},
			{
				InstanceName:         "other-snap",
				AdditionalComponents: []string{"other-comp1"},
			},
		})

		t := st.NewTask("fake-refresh-snap", "Doing a fake refresh")
		return []string{"some-snap", "other-snap"}, &snapstate.UpdateTaskSets{Refresh: []*state.TaskSet{state.NewTaskSet(t)}}, nil
	})
	defer restore()

	d := s.daemonWithFakeSnapManager(c)

	r := strings.NewReader(`{"action": "refresh", "snaps": ["some-snap", "other-snap"], "components": {"some-snap": ["some-comp1", "some-comp2"], "other-snap": ["other-comp1"]}}`)
	req, err := http.NewRequest("POST", "/v2/snaps", r)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st := d.Overlord().State()
	st.Lock()
	defer st.Unlock()

	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 1)

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Status(), check.Equals, state.DoneStatus)
	c.Check(err, check.IsNil)
	c.Check(chg.Kind(), check.Equals, "refresh-snap")
	c.Check(chg.Summary(), check.Equals, `Refresh snaps "some-snap" (with components "some-comp1", "some-comp2"), "other-snap" (with component "other-comp1")`)
}

func (s *snapsSuite) TestInstallWithComponentsSnapAlreadyInstalled(c *check.C) {
	defer daemon.MockSnapstateInstallComponents(func(ctx context.Context, st *state.State, names []string, info *snap.Info, vsets *snapasserts.ValidationSets, opts snapstate.Options) ([]*state.TaskSet, error) {
		c.Check(names, check.DeepEquals, []string{"comp1", "comp2"})
		c.Check(info.InstanceName(), check.Equals, "some-snap")
		t := st.NewTask("fake-install-component", "Doing a fake components install")
		return []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		c.Fatal("unexpected call to snapstateInstallWithGoal")
		return nil, nil, nil
	})()

	d := s.daemonWithFakeSnapManager(c)

	r := strings.NewReader(`{"action": "install", "components": ["comp1", "comp2"]}`)
	req, err := http.NewRequest("POST", "/v2/snaps/some-snap", r)
	c.Assert(err, check.IsNil)

	st := d.Overlord().State()
	st.Lock()
	si := &snap.SideInfo{
		RealName: "some-snap",
		Revision: snap.R(1),
		SnapID:   "some-snap-id",
	}

	snapstate.Set(st, "some-snap", &snapstate.SnapState{
		Active: true,
		Sequence: snapstatetest.NewSequenceFromRevisionSideInfos(
			[]*sequence.RevisionSideState{sequence.NewRevisionSideState(si, nil)},
		),
		Current: snap.R(1),
	})
	st.Unlock()

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st.Lock()

	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 1)

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Status(), check.Equals, state.DoneStatus)
	c.Check(err, check.IsNil)
	c.Check(chg.Kind(), check.Equals, "install-snap")
	c.Check(chg.Summary(), check.Equals, `Install "some-snap" snap with components "comp1", "comp2"`)
}

func (s *snapsSuite) TestManyInstallWithComponentsSnapAlreadyInstalled(c *check.C) {
	defer daemon.MockSnapstateInstallComponents(func(ctx context.Context, st *state.State, names []string, info *snap.Info, vsets *snapasserts.ValidationSets, opts snapstate.Options) ([]*state.TaskSet, error) {
		c.Check(names, check.DeepEquals, []string{"comp1", "comp2"})
		c.Check(info.InstanceName(), check.Equals, "some-snap-with-components")
		t := st.NewTask("fake-install-component", "Doing a fake components install")
		return []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	defer daemon.MockSnapstateInstallWithGoal(func(ctx context.Context, st *state.State, g snapstate.InstallGoal, opts snapstate.Options) ([]*snap.Info, []*state.TaskSet, error) {
		goal, ok := g.(*storeInstallGoalRecorder)
		c.Assert(ok, check.Equals, true, check.Commentf("unexpected InstallGoal type %T", g))
		c.Assert(goal.snaps, check.HasLen, 1)

		c.Check(goal.snaps[0].InstanceName, check.Equals, "some-snap")
		c.Check(goal.snaps[0].Components, check.HasLen, 0)

		t := st.NewTask("fake-install-snap", "Doing a fake install")
		return []*snap.Info{{}}, []*state.TaskSet{state.NewTaskSet(t)}, nil
	})()

	d := s.daemonWithFakeSnapManager(c)

	r := strings.NewReader(`{"action": "install", "snaps": ["some-snap", "some-snap-with-components"], "components": {"some-snap-with-components": ["comp1", "comp2"]}}`)
	req, err := http.NewRequest("POST", "/v2/snaps", r)
	c.Assert(err, check.IsNil)
	req.Header.Set("Content-Type", "application/json")

	st := d.Overlord().State()
	st.Lock()
	si := &snap.SideInfo{
		RealName: "some-snap-with-components",
		Revision: snap.R(1),
		SnapID:   "some-snap-id",
	}

	snapstate.Set(st, "some-snap-with-components", &snapstate.SnapState{
		Active: true,
		Sequence: snapstatetest.NewSequenceFromRevisionSideInfos(
			[]*sequence.RevisionSideState{sequence.NewRevisionSideState(si, nil)},
		),
		Current: snap.R(1),
	})
	st.Unlock()

	rsp := s.asyncReq(c, req, nil, actionIsExpected)

	st.Lock()

	chg := st.Change(rsp.Change)
	c.Assert(chg, check.NotNil)

	c.Check(chg.Tasks(), check.HasLen, 2)

	st.Unlock()
	s.waitTrivialChange(c, chg)
	st.Lock()

	c.Check(chg.Status(), check.Equals, state.DoneStatus)
	c.Check(err, check.IsNil)
	c.Check(chg.Kind(), check.Equals, "install-snap")

	// TODO: decide if we want to have a better summary that indicates that
	// the component was installed for an already installed snap. more
	// complicated code, but it could be nice to have.
	c.Check(chg.Summary(), check.Equals, `Install snaps "some-snap", "some-snap-with-components" (with components "comp1", "comp2")`)
}
