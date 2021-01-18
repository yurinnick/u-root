// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

//go:generate jsonenums -type=bootmode
type bootmode int

// bootmodes values defines where to load a OS package from.
const (
	Local bootmode = iota
	Network
)

func (b bootmode) String() string {
	return []string{"local", "network"}[b]
}

// SecurityConfig contains platform-specific data.
type SecurityConfig struct {
	// MinimalSignaturesMatch is the min number of signatures that must pass validation.
	MinimalSignaturesMatch int `json:"minimal_signatures_match"`
	//BootMode
	BootMode bootmode `json:"boot_mode"`
}

// loadSecurityConfig parses security_configuration.json file.
// It is expected to be in /etc.
func loadSecurityConfig(path string) (*SecurityConfig, error) {
	var sc SecurityConfig
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file %s due to: %v", path, err)
	}
	if err = json.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("cannot parse data - invalid security configuration in %s:  %v", path, err)
	}
	return &sc, nil
}
