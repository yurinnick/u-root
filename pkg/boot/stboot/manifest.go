// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stboot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// OSManifest describes the content and configuration of an OS package
// loaded by stboot.
type OSManifest struct {
	Label string `json:"label"`

	Kernel    string `json:"kernel"`
	Initramfs string `json:"initramfs"`
	Cmdline   string `json:"cmdline"`

	Tboot     string   `json:"tboot"`
	TbootArgs string   `json:"tboot_args"`
	ACMs      []string `json:"acms"`
}

// OSManifestFromFile parses a manifest from a json file
func OSManifestFromFile(src string) (*OSManifest, error) {
	mBytes, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, err
	}
	m, err := OSManifestFromBytes(mBytes)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// OSManifestFromBytes parses a manifest from a byte slice.
func OSManifestFromBytes(data []byte) (*OSManifest, error) {
	var m OSManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Write saves m to file named by stboot.ManifestName at a path named by dir.
func (m *OSManifest) Write(dir string) error {
	stat, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("not a directory: %s", dir)
	}

	buf, err := m.Bytes()
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, ManifestName)
	err = ioutil.WriteFile(dst, buf, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

// Bytes serializes a manifest stuct into a byte slice.
func (m *OSManifest) Bytes() ([]byte, error) {
	buf, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// Validate returns true if m is valid to be booted.
func (m *OSManifest) Validate() error {
	if m.Kernel == "" {
		return errors.New("manifest: missing kernel")
	}
	if m.Tboot != "" && len(m.ACMs) == 0 {
		return errors.New("manifest: tboot provided but missing ACM")
	}
	return nil
}
