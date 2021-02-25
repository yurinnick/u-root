// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"

	"github.com/vishvananda/netlink"
)

const HostConfigVersion int = 1

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
	Version          int         `json:"version"`
	NetworkMode      networkmode `json:"network_mode"`
	HostIP           string      `json:"host_ip"`
	DefaultGateway   string      `json:"gateway"`
	DNSServer        net.IP      `json:"dns"`
	ProvisioningURLs []string    `json:"provisioning_urls"`
	ID               string      `json:"identity"`
	Auth             string      `json:"authentication"`
	EntropySeed      string      `json:"entropy_seed"`

	isValidBasic   bool
	isValidNetwork bool

	hostIP           *netlink.Addr
	defaultGateway   *netlink.Addr
	provisioningURLs []*url.URL
	entropySeed      [32]byte
}

// Validate checks the integrety of hc. network controlls, if the
// network related settings are checked.
func (hc *HostConfig) Validate(network bool) error {
	if !hc.isValidBasic {
		// version
		if hc.Version != HostConfigVersion {
			return fmt.Errorf("version missmatch, want %d, got %d", HostConfigVersion, hc.Version)
		}
		// entropy seed
		e, err := hex.DecodeString(hc.EntropySeed)
		if err != nil || len(e) != 32 {
			return fmt.Errorf("entropy seed: 32 hex-encoded bytes expected")
		}
		copy(hc.entropySeed[:], e)
		hc.isValidBasic = true
	}
	if network && !hc.isValidNetwork {
		// absolute provisioning URLs
		if len(hc.ProvisioningURLs) == 0 {
			return fmt.Errorf("missing provisioning URLs")
		}
		for _, u := range hc.ProvisioningURLs {
			url, err := url.Parse(u)
			if err != nil {
				return fmt.Errorf("provisioning URLs: %v", err)
			}
			s := url.Scheme
			if s == "" || s != "http" && s != "https" {
				return fmt.Errorf("provisioning URL: missing or unsupported scheme in %s", url.String())
			}
			hc.provisioningURLs = append(hc.provisioningURLs, url)
		}
		// host ip and default gateway are required in case of static network mode
		if hc.NetworkMode == Static {
			a, err := netlink.ParseAddr(hc.HostIP)
			if err != nil {
				return fmt.Errorf("host ip: %v", err)
			}
			hc.hostIP = a
			a, err = netlink.ParseAddr(hc.DefaultGateway)
			if err != nil {
				return fmt.Errorf("default gateway: %v", err)
			}
			hc.defaultGateway = a
		}
		// identity is optional
		if hc.ID != "" {
			e, err := hex.DecodeString(hc.ID)
			if err != nil || len(e) != 32 {
				return fmt.Errorf("identity: 32 hex-encoded bytes expected")
			}
		}
		// authentication is optional
		if hc.Auth != "" {
			e, err := hex.DecodeString(hc.Auth)
			if err != nil || len(e) != 32 {
				return fmt.Errorf("authentication: 32 hex-encoded bytes expected")
			}
		}
		hc.isValidNetwork = true
	}
	return nil
}

func (hc *HostConfig) ParseHostIP() (*netlink.Addr, error) {
	if err := hc.Validate(true); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	return hc.hostIP, nil
}

func (hc *HostConfig) ParseDefaultGateway() (*netlink.Addr, error) {
	if err := hc.Validate(true); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	return hc.defaultGateway, nil
}

func (hc *HostConfig) ParseProvisioningURLs() ([]*url.URL, error) {
	if err := hc.Validate(true); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	return hc.provisioningURLs, nil
}

func (hc *HostConfig) ParseEntropySeed() (*[32]byte, error) {
	if err := hc.Validate(false); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	return &hc.entropySeed, nil
}
