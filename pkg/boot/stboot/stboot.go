// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stboot

import (
	"net"
	"strings"
)

const (
	// OSPackageExt is the file extension of OS packages
	OSPackageExt string = ".zip"
	// DefaultOSPackageName is the file name of the archive, which is expected to contain
	// the stboot configuration file along with the corresponding files
	DefaultOSPackageName string = "ospkg.zip"
	// ConfigName is the name of the stboot configuration file
	ConfigName string = "stconfig.json"
)

// ComposeIndividualOSPackagePrefix returns a host specific name prefix for OS package files.
func ComposeIndividualOSPackagePrefix(hwAddr net.HardwareAddr) string {
	prefix := hwAddr.String()
	prefix = strings.ReplaceAll(prefix, ":", "-")
	return prefix + "-"
}
