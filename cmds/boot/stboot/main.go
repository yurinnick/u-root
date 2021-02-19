// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/boot/stboot"
	"github.com/u-root/u-root/pkg/recovery"
	"github.com/u-root/u-root/pkg/ulog"
)

var (
	doDebug = flag.Bool("debug", false, "Print additional debug output")
	klog    = flag.Bool("klog", false, "Print output to all attached consoles via the kernel log")
	dryRun  = flag.Bool("dryrun", false, "Do everything except booting the loaded kernel")

	debug = func(string, ...interface{}) {}

	sc *SecurityConfig
	hc *HostConfig
)

// files at initramfs
const (
	securityConfigFile = "/etc/security_configuration.json"
	signingRootFile    = "/etc/ospkg_signing_root.pem"
	httpsRootsFile     = "/etc/https_roots.pem"
)

// files at STBOOT partition
const (
	hostConfigurationFile = "/host_configuration.json"
)

// files at STDATA partition
const (
	timeFixFile        = "stboot/etc/system_time_fix"
	localOSPkgDir      = "stboot/os_pkgs/local/"
	localBootOrderFile = "stboot/etc/local_boot_order"
	currentOSPkgFile   = "stboot/etc/current_ospkg_pathname"
)

var banner = `
  _____ _______   _____   ____   ____________
 / ____|__   __|  |  _ \ / __ \ / __ \__   __|
| (___    | |     | |_) | |  | | |  | | | |   
 \___ \   | |     |  _ <| |  | | |  | | | |   
 ____) |  | |     | |_) | |__| | |__| | | |   
|_____/   |_|     |____/ \____/ \____/  |_|   

`

var check = `           
           //\\
verified  //  \\
OS       //   //
        //   //
 //\\  //   //
//  \\//   //
\\        //
 \\      //
  \\    //
   \\__//
`

func main() {
	log.SetPrefix("stboot: ")
	ulog.KernelLog.SetLogLevel(ulog.KLogNotice)
	ulog.KernelLog.SetConsoleLogLevel(ulog.KLogInfo)

	flag.Parse()
	if *doDebug {
		debug = info
	}

	info(banner)

	/////////////////////////
	// Security configuration
	/////////////////////////
	var err error
	sc, err = loadSecurityConfig(securityConfigFile)
	if err != nil {
		reboot("Cannot find security_configuration.json: %v", err)
	}
	if *doDebug {
		str, _ := json.MarshalIndent(sc, "", "  ")
		info("Security configuration: %s", str)
	}

	////////////////////////////
	// Signing root certificate
	////////////////////////////

	pemBytes, err := ioutil.ReadFile(signingRootFile)
	if err != nil {
		reboot("loading signing root cert failed: %v", err)
	}
	debug("signing root certificate:\n%s", string(pemBytes))
	pemBlock, rest := pem.Decode(pemBytes)
	if pemBlock == nil {
		reboot("decoding signing root cert failed: %v", err)
	}
	if len(rest) > 0 {
		reboot("signing root cert: unexpeceted trailing data")
	}

	signingRoot, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		reboot("parsing signing root cert failed: %v", err)
	}

	////////////////////////////
	// https root certificates
	////////////////////////////
	httpsRoots := x509.NewCertPool()
	if sc.BootMode == Network {
		pemBytes, err = ioutil.ReadFile(httpsRootsFile)
		if err != nil {
			reboot("loading https root certs failed: %v", err)
		}
		if ok := httpsRoots.AppendCertsFromPEM(pemBytes); !ok {
			reboot("parsing https root certs failed")
		}
	}

	//////////////////////////////
	// STBOOT and STDATA partition
	//////////////////////////////
	err = findBootPartition()
	if err != nil {
		reboot("STBOOT partition: %v", err)
	}
	err = findDataPartition()
	if err != nil {
		reboot("STDATA partition: %v", err)
	}

	/////////////////////
	// Host configuration
	/////////////////////
	p := filepath.Join(bootPartitionMountPoint, hostConfigurationFile)
	bytes, err := ioutil.ReadFile(p)
	if err != nil {
		reboot("Failed to load host_configuration.json: %v", err)
	}
	err = json.Unmarshal(bytes, &hc)
	if err != nil {
		reboot("Failed to unmarshal host_configuration.json: %v", err)
	}
	if *doDebug {
		str, _ := json.MarshalIndent(hc, "", "  ")
		info("Host configuration: %s", str)
	}

	////////////////////
	// Time validatition
	////////////////////
	p = filepath.Join(dataPartitionMountPoint, timeFixFile)
	timeFixRaw, err := ioutil.ReadFile(p)
	if err != nil {
		reboot("time validation: %v", err)
	}
	buildTime, err := parseUNIXTimestamp(string(timeFixRaw))
	if err != nil {
		reboot("time validation: %v", err)
	}
	err = checkSystemTime(buildTime)
	if err != nil {
		reboot("%v", err)
	}

	////////////////
	// TXT self test
	////////////////
	txtHostSuport := false
	info("TXT self tests are not implementet yet.")
	if txtHostSuport {
		info("TXT is supported on this platform")
	}

	////////////////
	// Load OS package
	////////////////

	var ospkgFiles []string

	switch sc.BootMode {
	case Network:
		f, err := loadOSPackageFromNetwork()
		if err != nil {
			reboot("loading OS package failed: %v", err)
		}
		ospkgFiles = append(ospkgFiles, f)
	case Local:
		ff, err := loadOSPackageFromLocalStorage()
		if err != nil {
			reboot("loading OS package failed: %v", err)
		}
		ospkgFiles = append(ospkgFiles, ff...)
	default:
		reboot("unsupported boot mode: %s", sc.BootMode.String())
	}
	if len(ospkgFiles) == 0 {
		reboot("No OS packages found")
	}
	if *doDebug {
		info("OS packages to be processed:")
		for _, b := range ospkgFiles {
			info(b)
		}
	}

	//////////////////////
	// Process OS packages
	//////////////////////
	var bootImg boot.OSImage
	var ospkg *stboot.OSPackage
	for _, path := range ospkgFiles {
		info("Opening OS package %s", path)
		archive, err := ioutil.ReadFile(path)
		if err != nil {
			reboot("%v", err)
		}
		dpath := strings.TrimSuffix(path, stboot.OSPackageExt)
		dpath = dpath + stboot.DescriptorExt
		descriptor, err := ioutil.ReadFile(dpath)
		if err != nil {
			reboot("%v", err)
		}
		ospkg, err = stboot.NewOSPackage(archive, descriptor)
		if err != nil {
			debug("%v", err)
			continue
		}

		////////////////////
		// Verify OS package
		////////////////////
		// if *doDebug {
		// 	//TODO: write ospkg.info method
		// }

		n, valid, err := ospkg.Verify(signingRoot)
		if err != nil {
			debug("Error verifying OS package: %v", err)
			continue
		}
		if valid < sc.MinimalSignaturesMatch {
			debug("Not enough valid signatures: %d found, %d valid, %d required", n, valid, sc.MinimalSignaturesMatch)
			continue
		}

		debug("Signatures: %d found, %d valid, %d required", n, valid, sc.MinimalSignaturesMatch)
		info("OS package passed verification")
		info(check)

		/////////////
		// Extract OS
		/////////////
		bootImg, err = ospkg.OSImage(txtHostSuport)
		if err != nil {
			reboot("error parsing boot image: %v", err)
		}
		switch t := bootImg.(type) {
		case *boot.LinuxImage:
			if txtHostSuport {
				debug("TXT is supported on the host, but the os package doesn't provide tboot")
			}
			debug("got linux boot image from os package")
		case *boot.MultibootImage:
			debug("got tboot multiboot image from os package")
		default:
			reboot("unknown boot image type %T", t)
		}

		if sc.BootMode == Local {
			markCurrentOSpkg(path)
		}
		break
	} // end process-os-pkgs-loop
	if bootImg == nil {
		reboot("No usable OS package")
	}
	debug("boot image:\n %s", bootImg.String())

	///////////////////////
	// TPM Measurement
	///////////////////////
	info("Try TPM measurements")
	var toBeMeasured = [][]byte{}

	ospkgBytes, _ := ospkg.ArchiveBytes()
	descriptorBytes, _ := ospkg.DescriptorBytes()
	securityConfigBytes, _ := json.Marshal(sc)

	toBeMeasured = append(toBeMeasured, ospkgBytes)
	debug(" - OS package zip: %d bytes", len(ospkgBytes))
	toBeMeasured = append(toBeMeasured, descriptorBytes)
	debug(" - OS package descriptor: %d bytes", len(descriptorBytes))
	toBeMeasured = append(toBeMeasured, securityConfigBytes)
	debug(" - Security configuration json: %d bytes", len(securityConfigBytes))
	toBeMeasured = append(toBeMeasured, signingRoot.Raw)
	debug(" - Signing root cert ASN1 DER content: %d bytes", len(signingRoot.Raw))
	toBeMeasured = append(toBeMeasured, httpsRoots.Subjects()...)
	debug(" - HTTPS roots: %d certificates", len(httpsRoots.Subjects()))

	// try to measure
	if err = measureTPM(toBeMeasured...); err != nil {
		info("TPM measurements failed: %v", err)
	}

	//////////
	// Boot OS
	//////////
	if *dryRun {
		debug("Dryrun mode: will not boot")
		return
	}
	info("Loading boot image into memory")
	err = bootImg.Load(*doDebug)
	if err != nil {
		reboot("%s", err)
	}
	info("Handing over controll - kexec")
	err = boot.Execute()
	if err != nil {
		reboot("%v", err)
	}

	reboot("unexpected return from kexec")
}

func markCurrentOSpkg(file string) {
	f := filepath.Join(dataPartitionMountPoint, currentOSPkgFile)
	rel, err := filepath.Rel(filepath.Dir(f), file)
	if err != nil {
		reboot("failed to indicate current OS package: %v", err)
	}
	rel = rel + string('\n')
	if err = ioutil.WriteFile(f, []byte(rel), os.ModePerm); err != nil {
		reboot("failed to indicate current OS package: %v", err)
	}
}

func loadOSPackageFromNetwork() (string, error) {
	info("Setting up network interface")
	switch hc.NetworkMode {
	case Static:
		err := configureStaticNetwork()
		if err != nil {
			return "", fmt.Errorf("cannot set up IO: %v", err)
		}
	case DHCP:
		err := configureDHCPNetwork()
		if err != nil {
			return "", fmt.Errorf("cannot set up IO: %v", err)
		}
	}
	info("Downloading OS package")
	dest, err := tryDownload(hc.ProvisioningURLs, stboot.DefaultOSPackageName)
	if err != nil {
		return "", fmt.Errorf("loading %s from provisioning servers: %v", stboot.DefaultOSPackageName, err)
	}
	return dest, nil
}

func loadOSPackageFromLocalStorage() ([]string, error) {
	f := filepath.Join(dataPartitionMountPoint, localBootOrderFile)
	return parseLocalBootOrder(f)
}

func parseLocalBootOrder(bootOrderFile string) ([]string, error) {
	ret := make([]string, 0)

	f, err := os.Open(bootOrderFile)
	if err != nil {
		return ret, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		p := filepath.Join(dataPartitionMountPoint, localOSPkgDir, scanner.Text())
		ret = append(ret, p)
	}

	if err := scanner.Err(); err != nil {
		return ret, err
	}
	return ret, nil
}

//reboot trys to reboot the system in an infinity loop
func reboot(format string, v ...interface{}) {
	if *klog {
		info(format, v...)
		info("REBOOT!")
	}
	for {
		recover := recovery.SecureRecoverer{
			Reboot:   true,
			Debug:    true,
			RandWait: true,
		}
		err := recover.Recover(fmt.Sprintf(format, v...))
		if err != nil {
			continue
		}
	}
}

func info(format string, v ...interface{}) {
	if *klog {
		ulog.KernelLog.Printf("stboot: "+format, v...)
	} else {
		log.Printf(format, v...)
	}
}
