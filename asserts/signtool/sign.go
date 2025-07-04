// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2023 Canonical Ltd
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

// Package signtool offers tooling to sign assertions.
package signtool

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/snapcore/snapd/asserts"
)

var (
	Stdout = os.Stdout
)

// Options specifies the complete input for signing an assertion.
type Options struct {
	// KeyID specifies the key id of the key to use
	KeyID string

	// AccountKey optionally holds the account-key for the key to use,
	// used for cross-checking
	AccountKey *asserts.AccountKey

	// Statement is used as input to construct the assertion
	// it's a mapping encoded as JSON
	// of the header fields of the assertion
	// plus an optional pseudo-header "body" to specify
	// the body of the assertion
	Statement []byte

	// Complement specifies complementary headers to what is in
	// Statement, for use by tools that fill-in/compute some of
	// the headers. Headers appearing both in Statement and
	// Complement are an error, except for "type" that needs
	// instead to match if present. Pseudo-header "body" can also
	// be specified here.
	Complement map[string]any

	// UpdateTimestamp is used to update the output "timestamp"
	// header to the current time
	UpdateTimestamp bool
}

// Sign produces the text of a signed assertion as specified by opts.
func Sign(opts *Options, keypairMgr asserts.KeypairManager) ([]byte, error) {
	var headers map[string]any
	err := json.Unmarshal(opts.Statement, &headers)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the assertion input as JSON: %v", err)
	}

	for name, value := range opts.Complement {
		if v, ok := headers[name]; ok {
			if name == "type" {
				if v != value {
					return nil, fmt.Errorf("repeated assertion type does not match")
				}
			} else {
				return nil, fmt.Errorf("complementary header %q clashes with assertion input", name)
			}
		}
		headers[name] = value
	}

	typCand, ok := headers["type"]
	if !ok {
		return nil, fmt.Errorf("missing assertion type header")
	}
	typStr, ok := typCand.(string)
	if !ok {
		return nil, fmt.Errorf("assertion type must be a string, not: %v", typCand)
	}
	typ := asserts.Type(typStr)
	if typ == nil {
		return nil, fmt.Errorf("invalid assertion type: %v", headers["type"])
	}

	var body []byte
	if bodyCand, ok := headers["body"]; ok {
		bodyStr, ok := bodyCand.(string)
		if !ok {
			return nil, fmt.Errorf("body if specified must be a string")
		}
		body = []byte(bodyStr)
		delete(headers, "body")
	}

	adb, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		KeypairManager: keypairMgr,
	})
	if err != nil {
		return nil, err
	}

	if opts.AccountKey != nil {
		// cross-check with the actual account-key if provided
		accKey := opts.AccountKey
		if accKey.PublicKeyID() != opts.KeyID {
			return nil, fmt.Errorf("internal error: key id does not match the signing account-key")
		}
		if accKey.AccountID() != headers["authority-id"] {
			return nil, fmt.Errorf("authority-id does not match the account-id of the signing account-key")
		}
		if accKey.ConstraintsPrecheck(typ, headers) != nil {
			return nil, fmt.Errorf("the assertion headers do not match the constraints of the signing account-key")
		}
	}

	if typ.JSONBody() && len(body) != 0 {
		body, err = reformatJSON(body)
		if err != nil {
			return nil, fmt.Errorf("cannot reformat body: %v", err)
		}
	}

	if opts.UpdateTimestamp {
		// Update the "timestamp" field with the current time in RFC3339 format.
		headers["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}

	a, err := adb.Sign(typ, headers, body, opts.KeyID)
	if err != nil {
		return nil, err
	}

	return asserts.Encode(a), nil
}

func reformatJSON(raw []byte) ([]byte, error) {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("cannot unmarshal unformatted JSON: %v", err)
	}

	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot marshal into formatted JSON: %v", err)
	}
	return raw, nil
}
