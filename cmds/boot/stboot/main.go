// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/boot/stboot"
	"github.com/u-root/u-root/pkg/crypto"
	"github.com/u-root/u-root/pkg/recovery"
	"github.com/u-root/u-root/pkg/ulog"
)

var (
	noMeasuredBoot = flag.Bool("no-measurement", false, "Do not extend PCRs with measurements of the loaded OS")
	doDebug        = flag.Bool("debug", false, "Print additional debug output")
	klog           = flag.Bool("klog", false, "Print output to all attached consoles via the kernel log")
	dryRun         = flag.Bool("dryrun", false, "Do everything except booting the loaded kernel")

	debug = func(string, ...interface{}) {}

	sc                 *SecurityConfig
	hc                 *HostConfig
	txtSupportedByHost bool
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
OS is     //  \\
valid    //   //
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
	// Ssigning root certificate
	////////////////////////////
	signingRootPEM, err := ioutil.ReadFile(signingRootFile)
	if err != nil {
		reboot("Signing root certificate missing: %v", err)
	}
	debug("Signing Root: %s", string(signingRootPEM))

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
	txtSupportedByHost = false
	info("TXT self tests are not implementet yet.")
	if !txtSupportedByHost {
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
	var osi boot.OSImage
	for _, path := range ospkgFiles {
		info("Opening OS package %s", path)
		ospkg, err := stboot.OSPackageFromArchive(path)
		if err != nil {
			debug("%v", err)
			continue
		}

		////////////////////
		// Verify OS package
		////////////////////
		if *doDebug {
			str, _ := json.MarshalIndent(ospkg.Manifest, "", "  ")
			info("OS package manifest: %s", str)
		} else {
			info("Label: %s", ospkg.Manifest.Label)
		}

		n, valid, err := ospkg.Verify(signingRootPEM)
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
		osi, err = extractOS(ospkg)
		if err != nil {
			debug("%v", err)
			continue
		}

		if sc.BootMode == Local {
			markCurrentOSpkg(path)
		}
		break
	} // end process-os-pkgs-loop

	if osi == nil {
		reboot("No usable OS package")
	}

	info("Operating system: %s", osi.Label())
	debug("%s", osi.String())

	///////////////////////
	// Measure OS into PCRs
	///////////////////////
	if *noMeasuredBoot {
		info("WARNING: measured boot disabled!")
	} else {
		// TODO: measure osi byte stream not its label
		err = crypto.TryMeasureData(crypto.BootConfigPCR, []byte(osi.Label()), osi.Label())
		if err != nil {
			reboot("measured boot failed: %v", err)
		}
		// TODO: measure security_configuration.json and files from data partition
	}

	//////////
	// Boot OS
	//////////
	if *dryRun {
		debug("Dryrun mode: will not boot")
		return
	}
	info("Loading operating system into memory: \n%s", osi.String())
	err = osi.Load(*doDebug)
	if err != nil {
		reboot("%s", err)
	}
	info("Handing over controll now")
	err = boot.Execute()
	if err != nil {
		reboot("%v", err)
	}

	reboot("unexpected return from kexec")

}

func extractOS(ospkg *stboot.OSPackage) (boot.OSImage, error) {
	debug("Looking for operating system with TXT")
	txt := true
	osiTXT, err := ospkg.OSImage(txt)
	if err != nil {
		debug("%v", err)
	}
	debug("Looking for non-TXT fallback operating system")
	osiFallback, err := ospkg.OSImage(!txt)
	if err != nil {
		debug("%v", err)
	}

	switch {
	case osiTXT != nil && osiFallback != nil && txtSupportedByHost:
		info("Choosing operating system with TXT")
		return osiTXT, nil
	case osiTXT != nil && osiFallback != nil && !txtSupportedByHost:
		info("Choosing non-TXT fallback operating system")
		return osiFallback, nil
	case osiTXT != nil && osiFallback == nil && txtSupportedByHost:
		info("Choosing operating system with TXT")
		return osiTXT, nil
	case osiTXT != nil && osiFallback == nil && !txtSupportedByHost:
		return nil, fmt.Errorf("TXT not supported by host, no fallback OS provided by OS package")
	case osiTXT == nil && osiFallback != nil && txtSupportedByHost:
		info("Choosing non-TXT fallback operating system")
		return osiFallback, nil
	case osiTXT == nil && osiFallback != nil && !txtSupportedByHost:
		info("Choosing non-TXT fallback operating system")
		return osiFallback, nil
	case osiTXT == nil && osiFallback == nil:
		return nil, fmt.Errorf("No operating system found in OS package")
	default:
		return nil, fmt.Errorf("Unexpected error while extracting OS")
	}
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
