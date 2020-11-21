// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

//go:generate jsonenums -type=networkmode
type networkmode int

// networkmode values defines where to load a OS package from.
const (
	Static networkmode = iota
	DHCP
)

func (n networkmode) String() string {
	return []string{"static", "dhcp"}[n]
}

// HostConfig contains configuration data for a System Transparency host.
type HostConfig struct {
	NetworkMode      networkmode `json:"network_mode"`
	HostIP           string      `json:"host_ip"`
	DefaultGateway   string      `json:"gateway"`
	DNSServer        string      `json:"dns"`
	ProvisioningURLs []string    `json:"provisioning_urls"`
}

// loadHoatConfig parses host_configuration.json file.
func loadHostConfig(path string) (*HostConfig, error) {
	var hc HostConfig
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file %s due to: %v", path, err)
	}
	if err = json.Unmarshal(data, &hc); err != nil {
		return nil, fmt.Errorf("cannot parse data - invalid security configuration in %s:  %v", path, err)
	}
	return &hc, nil
}
