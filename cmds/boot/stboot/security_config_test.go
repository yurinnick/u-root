// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadSecurityConf(t *testing.T) {
	h, err := loadSecurityConfig("testdata/security_configuration.json")
	require.NoError(t, err)
	require.Equal(t, Local, h.BootMode)
}

func TestLoadSecurityConfigInvalid(t *testing.T) {
	_, err := loadSecurityConfig("testdata/security_configuration_invalid.json")
	require.Error(t, err)
}
