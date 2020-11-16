// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// stconfig is a configuration tool to create and manage artifacts for
// System Transparency Boot. Artifacts are ment to be uploaded to a
// remote provisioning server.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	// Author is the author
	Author = "Jens Drenhaus"
	// HelpText is the command line help
	HelpText = "stmanager can be used for managing System Transparency OS packages"

	OSPackageDefaultName = "system-transparency-os-package.zip"
)

var goversion string

var (
	create            = kingpin.Command("create", "Create a OS package from the provided operating system files")
	createOut         = create.Flag("out", "Path to output initramfs file. Defaults to current directory").String()
	createLabel       = create.Flag("label", "Name of the boot configuration. Defaults to 'System Tarnsparency OS package <kernel>'").String()
	createKernel      = create.Flag("kernel", "Operation system kernel").Required().ExistingFile()
	createInitramfs   = create.Flag("initramfs", "Operation system initramfs").ExistingFile()
	createCmdline     = create.Flag("cmd", "Kernel command line").String()
	createTboot       = create.Flag("tboot", "Pre-execution module that sets up TXT").ExistingFile()
	createTbootArgs   = create.Flag("tcmd", "tboot command line").String()
	createRootCert    = create.Flag("cert", "Root certificate of certificates used for signing").Required().ExistingFile()
	createACM         = create.Flag("acm", "Authenticated Code Module for TXT. This can be a path to single ACM or directory containig multiple ACMs.").ExistingFileOrDir()
	createAllowNonTXT = create.Flag("unsave", "Allow booting without TXT").Bool()

	sign            = kingpin.Command("sign", "Sign the binary inside the provided OS package")
	signPrivKeyFile = sign.Flag("key", "Private key for signing").Required().ExistingFile()
	signCertFile    = sign.Flag("cert", "Certificate corresponding to the private key").Required().ExistingFile()
	signOSPackage   = sign.Arg("OS package", "Archive created by 'stconfig create'").Required().ExistingFile()

	show          = kingpin.Command("sho", "Unpack OS package  file into directory")
	showOSPackage = show.Arg("OS package", "Archive containing the boot files").Required().ExistingFile()
)

func main() {
	log.SetPrefix("stmanager: ")
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version(goversion).Author(Author)
	kingpin.CommandLine.Help = HelpText

	switch kingpin.Parse() {
	case create.FullCommand():
		out, err := checkOutPath(*createOut)
		if err != nil {
			log.Fatal(err)
		}

		label := checkLabel(*createLabel)

		acms, err := checkACMs(*createACM)
		if err != nil {
			log.Fatal(err)
		}

		if err := packOSPackage(out, label, *createKernel, *createInitramfs, *createCmdline, *createTboot, *createTbootArgs, *createRootCert, acms, *createAllowNonTXT); err != nil {
			log.Fatal(err)
		}
	case sign.FullCommand():
		if err := addSignatureToOSPackage(*signOSPackage, *signPrivKeyFile, *signCertFile); err != nil {
			log.Fatal(err)
		}
	case show.FullCommand():
		if err := unpackOSPackage(*showOSPackage); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Command not found")
	}
}

func checkOutPath(out string) (string, error) {
	if out == "" {
		out = OSPackageDefaultName
	}

	dir := filepath.Dir(out)
	if _, err := os.Stat(dir); err != nil {
		return "", err
	}

	ext := filepath.Ext(out)
	if ext != ".zip" {
		out = out + ".zip"
	}
	return out, nil
}

func checkLabel(label string) string {
	if label == "" {
		k := filepath.Base(*createKernel)
		return fmt.Sprintf("System Tarnsparency OS Package %s", k)
	}
	return label
}

func checkACMs(acm string) ([]string, error) {
	var acms []string
	if *createACM != "" {
		stat, err := os.Stat(*createACM)
		if err != nil {
			return []string{}, err
		}
		if stat.IsDir() {
			err := filepath.Walk(*createACM, func(path string, info os.FileInfo, err error) error {
				if info.IsDir() {
					if info.Name() == filepath.Base(*createACM) {
						return nil // skip root
					}
					log.Fatalf("%s must contain acm files only. Found %s", *createACM, path)
				}
				acms = append(acms, path)
				return nil
			})
			if err != nil {
				return []string{}, err
			}
		} else {
			acms = append(acms, *createACM)
		}
	}
	return acms, nil
}
