// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/u-root/u-root/pkg/boot/stboot"
)

func packOSPackage(out, label, kernel, initramfs, cmdline, tboot, tbootArgs, rootCert string, acms []string) error {
	ospkg, err := stboot.InitOSPackage(out, label, kernel, initramfs, cmdline, tboot, tbootArgs, rootCert, acms)
	if err != nil {
		return err
	}

	err = ospkg.Pack()
	if err != nil {
		return err
	}

	fmt.Println(filepath.Base(ospkg.Archive))
	return ospkg.Clean()

}

func addSignatureToOSPackage(osPackage, privKey, cert string) error {
	ospkg, err := stboot.OSPackageFromArchive(osPackage)
	if err != nil {
		return err
	}

	log.Print("Signing OS package ...")
	log.Printf("private key: %s", privKey)
	log.Printf("certificate: %s", cert)
	err = ospkg.Sign(privKey, cert)
	if err != nil {
		return err
	}

	if err = ospkg.Pack(); err != nil {
		return err
	}

	log.Printf("Signatures included: %d", ospkg.NumSignatures)
	return ospkg.Clean()
}

func unpackOSPackage(ospkgPath string) error {
	ospkg, err := stboot.OSPackageFromArchive(ospkgPath)
	if err != nil {
		return err
	}

	log.Println("Archive unpacked into: " + ospkg.Dir)
	return nil
}
