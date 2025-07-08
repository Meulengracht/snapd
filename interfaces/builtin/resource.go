// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
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

package builtin

import (
	"fmt"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/snap"
)

const resourceSummary = `allows dependencies on services between snaps`

const resourceBaseDeclarationSlots = `
  resource:
    allow-installation:
      slot-snap-type:
        - app
        - core
    allow-connection:
      -
        slot-names:
          - network
          - network-pre
          - systemd-udev-settle
        slot-snap-type:
          - core
      -
        slot-snap-type:
          - app
    deny-auto-connection: true
`

// resourceInterface allows snaps to define service dependency and ordering between
// each other.
type resourceInterface struct{}

func (iface *resourceInterface) Name() string {
	return "resource"
}

func (iface *resourceInterface) StaticInfo() interfaces.StaticInfo {
	return interfaces.StaticInfo{
		Summary:              resourceSummary,
		ImplicitOnCore:       true,
		ImplicitOnClassic:    true,
		BaseDeclarationSlots: resourceBaseDeclarationSlots,
	}
}

func validateResourceScope(slotName, scope string) error {
	switch scope {
	case "system", "user":
		return nil
	}
	return fmt.Errorf("resource slot %s: scope must be either 'system' or 'user'", slotName)
}

func (iface *resourceInterface) BeforePrepareSlot(slot *snap.SlotInfo) error {
	content, ok := slot.Attrs["resource"].(string)
	if !ok || len(content) == 0 {
		if slot.Attrs == nil {
			slot.Attrs = make(map[string]any)
		}
		// content defaults to "slot" name if unspecified
		slot.Attrs["resource"] = slot.Name
	}

	scope, ok := slot.Attrs["scope"].(string)
	if !ok || len(scope) == 0 {
		return fmt.Errorf("resource slot %s: 'scope' is required", slot.Name)
	}
	return validateResourceScope(slot.Name, scope)
}

func validateResourceRelation(plugName, relation string) error {
	switch relation {
	case "after", "before", "bind-after", "bind-before":
		return nil
	}
	return fmt.Errorf("resource plug %s: invalid 'relation' defined: %s", relation)
}

func (iface *resourceInterface) BeforePreparePlug(plug *snap.PlugInfo) error {
	resource, ok := plug.Attrs["resource"].(string)
	if !ok || len(resource) == 0 {
		if plug.Attrs == nil {
			plug.Attrs = make(map[string]any)
		}
		// resource defaults to "plug" name if unspecified
		plug.Attrs["resource"] = plug.Name
	}

	relation, ok := plug.Attrs["relation"].(string)
	if !ok || len(relation) == 0 {
		// relation defaults to 'after'
		plug.Attrs["relation"] = "after"
		return nil
	}
	return validateResourceRelation(plug.Name, relation)
}

func (iface *resourceInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	return true
}

func init() {
	registerIface(&resourceInterface{})
}
