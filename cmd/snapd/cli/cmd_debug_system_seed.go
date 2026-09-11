// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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
 */

package cli

import (
	"errors"
	"fmt"

	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/release"
)

type cmdDebugCreateSystemSeed struct {
	waitMixin
	Positional struct {
		Label string `positional-arg-name:"<label>" required:"yes"`
	} `positional-args:"yes" required:"yes"`
}

type cmdDebugTrySystemSeed struct {
	Positional struct {
		Label string `positional-arg-name:"<label>" required:"yes"`
	} `positional-args:"yes" required:"yes"`
}

type cmdDebugAcceptSystemSeed struct {
	Positional struct {
		Label string `positional-arg-name:"<label>" required:"yes"`
	} `positional-args:"yes" required:"yes"`
}

type cmdDebugRunSystemStatus struct{}

func init() {
	commands := []*cmdInfo{
		addDebugCommand("create-system-seed", "Create a system seed for the boot-from-seed PoC", "Create a system seed for the boot-from-seed PoC.", func() flags.Commander {
			return &cmdDebugCreateSystemSeed{}
		}, nil, nil),
		addDebugCommand("try-system-seed", "Try a system seed on the next boot", "Try a system seed on the next boot.", func() flags.Commander {
			return &cmdDebugTrySystemSeed{}
		}, nil, nil),
		addDebugCommand("accept-system-seed", "Accept the booted system seed", "Accept the booted system seed.", func() flags.Commander {
			return &cmdDebugAcceptSystemSeed{}
		}, nil, nil),
		addDebugCommand("run-system-status", "Show the run-system boot state", "Show the run-system boot state.", func() flags.Commander {
			return &cmdDebugRunSystemStatus{}
		}, nil, nil),
	}
	if release.OnClassic {
		for _, command := range commands {
			command.hidden = true
		}
	}
}

func checkRunSystemCommandAvailable() error {
	if release.OnClassic {
		return errors.New("run-system debug commands are not available on classic systems")
	}
	return nil
}

func (x *cmdDebugCreateSystemSeed) Execute(args []string) error {
	if err := checkRunSystemCommandAvailable(); err != nil {
		return err
	}
	chgID, err := x.client.CreateSystemSeed(x.Positional.Label)
	if err != nil {
		return err
	}
	if _, err := x.wait(chgID); err != nil {
		return err
	}
	fmt.Fprintf(Stdout, "created system seed %s\n", x.Positional.Label)
	return nil
}

func (x *cmdDebugTrySystemSeed) Execute(args []string) error {
	if err := checkRunSystemCommandAvailable(); err != nil {
		return err
	}
	return boot.SetTryRunSystem(x.Positional.Label)
}

func (x *cmdDebugAcceptSystemSeed) Execute(args []string) error {
	if err := checkRunSystemCommandAvailable(); err != nil {
		return err
	}
	return boot.PromoteTriedRunSystem(x.Positional.Label)
}

func (x *cmdDebugRunSystemStatus) Execute(args []string) error {
	if err := checkRunSystemCommandAvailable(); err != nil {
		return err
	}
	state, err := boot.CurrentRunSystem()
	if err != nil {
		return err
	}
	fmt.Fprintf(Stdout, "run_system=%s\ntry_run_system=%s\n", state.Current, state.Try)
	return nil
}
