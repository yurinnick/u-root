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
	"time"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	// Author is the author
	Author = "Jens Drenhaus"
	// HelpText is the command line help
	HelpText = "stmanager can be used for managing System Transparency OS packages"

	DefaultPackageName  = "system-transparency-os-package.zip"
	DefaultCertName     = "cert.pem"
	DefaultRootCertName = "rootcert.pem"
	DefaultKeyName      = "key.pem"
	DefaultRootKeyName  = "rootkey.pem"
	DateFormat          = "02 Jan 06 15:04 UTC" //time.RFC822
)

var goversion string

var (
	create          = kingpin.Command("create", "Create a OS package from the provided operating system files")
	createOut       = create.Flag("out", "Path to output ZIP archive file. Defaults to "+DefaultPackageName).String()
	createLabel     = create.Flag("label", "Short description of the boot configuration. Defaults to 'System Tarnsparency OS package <kernel>'").String()
	createPkgURL    = create.Flag("pkg-url", "URL of the OS package in case of network boot mode").String()
	createKernel    = create.Flag("kernel", "Operation system kernel").Required().ExistingFile()
	createInitramfs = create.Flag("initramfs", "Operation system initramfs").ExistingFile()
	createCmdline   = create.Flag("cmd", "Kernel command line").String()
	createTboot     = create.Flag("tboot", "Pre-execution module that sets up TXT").ExistingFile()
	createTbootArgs = create.Flag("tcmd", "tboot command line").String()
	createACM       = create.Flag("acm", "Authenticated Code Module for TXT. This can be a path to single ACM or directory containig multiple ACMs.").ExistingFileOrDir()

	sign            = kingpin.Command("sign", "Sign the provided OS package")
	signPrivKeyFile = sign.Flag("key", "Private key for signing").Required().ExistingFile()
	signCertFile    = sign.Flag("cert", "Certificate corresponding to the private key").Required().ExistingFile()
	signOSPackage   = sign.Arg("OS package", "Archive created by 'stconfig create'").Required().ExistingFile()

	show          = kingpin.Command("show", "Unpack OS package  file into directory")
	showOSPackage = show.Arg("OS package", "Archive containing the boot files").Required().ExistingFile()

	keygen           = kingpin.Command("keygen", "Generate certificates for signing OS packages using ED25529 keys")
	keygenRootCert   = kingpin.Flag("rootCert", "Root certificate in PEM format to sign the new certificate. Ignored if --isCA is set").ExistingFile()
	keygenRootKey    = kingpin.Flag("rootKey", "Root key in PEM format to sign the new certificate. Ignored if --isCA is set").ExistingFile()
	keygenIsCA       = kingpin.Flag("isCA", "Generate a self signed root certificate.").Bool()
	keygenValidFrom  = kingpin.Flag("validFrom", "Date formatted as '"+DateFormat+"'. Defaults to time of creation").String()
	keygenValidUntil = kingpin.Flag("validUntil", "Date formatted as '"+DateFormat+"'. Defaults to time of creation").String()
	keygenCertOut    = kingpin.Flag("certOut", "Output certificate file. Defaults to "+DefaultCertName+" or "+DefaultRootCertName+" if --isCA is set.").String()
	keygenKeyOut     = kingpin.Flag("keyOut", "Output key file. Defaults to "+DefaultKeyName+" or "+DefaultRootKeyName+" if --isCA is set.").String()
)

func main() {
	log.SetPrefix("stmanager: ")
	log.SetFlags(0)
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version(goversion).Author(Author)
	kingpin.CommandLine.Help = HelpText

	switch kingpin.Parse() {
	case create.FullCommand():
		checkCreateOut()
		checkCreateLabel()

		acms, err := checkCreateACMs(*createACM)
		if err != nil {
			log.Fatal(err)
		}

		if err := createCmd(*createOut, *createLabel, *createPkgURL, *createKernel, *createInitramfs, *createCmdline, *createTboot, *createTbootArgs, acms); err != nil {
			log.Fatal(err)
		}
	case sign.FullCommand():
		if err := signCmd(*signOSPackage, *signPrivKeyFile, *signCertFile); err != nil {
			log.Fatal(err)
		}
	case show.FullCommand():
		if err := showCmd(*showOSPackage); err != nil {
			log.Fatal(err)
		}
	case keygen.FullCommand():
		checkKeygenOuts()

		notBefore, err := parseTime(*keygenValidFrom)
		if err != nil {
			log.Fatalf("failed to parse 'validFrom' date: %v, try --help", err)
		}
		notAfter, err := parseTime(*keygenValidUntil)
		if err != nil {
			log.Fatalf("failed to parse 'validUntil' date: %v, try --help", err)
		}

		if *keygenIsCA {
			if err := keygenCmd("", "", notBefore, notAfter, *keygenCertOut, *keygenKeyOut); err != nil {
				log.Fatal(err)
			}
		} else {
			if *keygenRootCert == "" || *keygenRootKey == "" {
				log.Fatal("missing flag, try --help")
			}
			if err := keygenCmd(*keygenRootCert, *keygenRootKey, notBefore, notAfter, *keygenCertOut, *keygenKeyOut); err != nil {
				log.Fatal(err)
			}
		}
	default:
		log.Fatal("command not found")
	}
}

func checkCreateOut() {
	if *createOut == "" {
		*createOut = DefaultPackageName
	} else {
		dir := filepath.Dir(*createOut)
		if _, err := os.Stat(dir); err != nil {
			log.Fatal(err)
		}

		ext := filepath.Ext(*createOut)
		if ext != ".zip" {
			*createOut = *createOut + ".zip"
		}
	}
}

func checkKeygenOuts() {
	if *keygenCertOut == "" {
		if *keygenIsCA {
			*keygenCertOut = DefaultRootCertName
		} else {
			*keygenCertOut = DefaultCertName
		}
	} else {
		dir := filepath.Dir(*keygenCertOut)
		if _, err := os.Stat(dir); err != nil {
			log.Fatal(err)
		}
	}

	if *keygenKeyOut == "" {
		if *keygenIsCA {
			*keygenKeyOut = DefaultRootKeyName
		} else {
			*keygenKeyOut = DefaultKeyName
		}
	} else {
		dir := filepath.Dir(*keygenKeyOut)
		if _, err := os.Stat(dir); err != nil {
			log.Fatal(err)
		}
	}
}

func checkCreateLabel() {
	if *createLabel == "" {
		k := filepath.Base(*createKernel)
		*createLabel = fmt.Sprintf("System Tarnsparency OS Package %s", k)
	}
}

func checkCreateACMs(acm string) ([]string, error) {
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

func parseTime(date string) (time.Time, error) {
	if len(date) == 0 {
		return time.Now(), nil
	}
	return time.Parse(DateFormat, date)
}
