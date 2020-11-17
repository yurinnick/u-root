// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckOutPath(t *testing.T) {
	var testCases = map[string]string{
		"":             OSPackageDefaultName,
		"some-pkg":     "some-pkg.zip",
		"some-pkg.zip": "some-pkg.zip",
	}
	for input, expected := range testCases {
		r, err := checkOutPath(input)
		require.NoError(t, err)
		require.Equal(t, r, expected)
	}
	r, err := checkOutPath("some/non/existing/folder/name.zip")
	require.Error(t, err)
	require.Equal(t, r, "")

	r, err = checkOutPath("../stmanager/name.zip")
	require.NoError(t, err)
	require.Equal(t, r, "")
}
