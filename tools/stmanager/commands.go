// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"net"
	"path/filepath"

	"github.com/u-root/u-root/pkg/boot/stboot"
)

func packOSPackage(outDir, label, kernel, initramfs, cmdline, tboot, tbootArgs, rootCert string, acms []string, allowNonTXT bool, mac string) error {
	var individual string
	if mac != "" {
		hwAddr, err := net.ParseMAC(mac)
		if err != nil {
			return err
		}
		individual = stboot.ComposeIndividualOSPackagePrefix(hwAddr)
	}

	ospkg, err := stboot.InitOSPackage(outDir, label, kernel, initramfs, cmdline, tboot, tbootArgs, rootCert, acms, allowNonTXT)
	if err != nil {
		return err
	}

	if individual != "" {
		name := filepath.Base(ospkg.Archive)
		name = individual + name
		ospkg.Archive = filepath.Join(filepath.Dir(ospkg.Archive), name)
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
