// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
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

type HostConfig struct {
	HostIP           string   `json:"host_ip"`
	DefaultGateway   string   `json:"gateway"`
	DNSServer        string   `json:"dns"`
	ProvisioningURLs []string `json:"provisioning_urls"`
	NTPURLs          []string `json:"ntp_urls"`
}

// files at initramfs
const (
	securityConfigFile = "/etc/security_configuration.json"
	httpsRootsFile     = "/etc/https_roots.pem"
)

// files at STBOOT partition
const (
	hostConfigurationFile = "/host_configuration.json"
)

// files at STDATA partition
const (
	timeFixFile      = "stboot/etc/system_time_fix"
	newDir           = "stboot/os_pkgs/new/"
	knownGoodDir     = "stboot/os_pkgs/known_good/"
	invalidDir       = "stboot/os_pkgs/invalid/"
	currentOSPkgFile = "stboot/os_pkgs/current-ospkg.zip"
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
	if len(sc.Fingerprints) == 0 {
		reboot("No root certificate fingerprints found in security_configuration.json")
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

	// load host configuration
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

	//////////
	// Network
	//////////
	if sc.BootMode == NetworkStatic {
		err = configureStaticNetwork()
		if err != nil {
			reboot("Cannot set up IO: %v", err)
		}
	}

	if sc.BootMode == NetworkDHCP {
		err = configureDHCPNetwork()
		if err != nil {
			reboot("Cannot set up IO: %v", err)
		}
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
	txtSupportedByHost = runTxtTests(*doDebug)
	if !txtSupportedByHost {
		info("WARNING: No TXT Support!")
	}
	info("TXT is supported on this platform")

	////////////////
	// Load OS package
	////////////////

	var ospkgFiles []string

	switch sc.BootMode {
	case NetworkStatic, NetworkDHCP:
		f, err := loadOSPackageFromNetwork()
		if err != nil {
			reboot("error loading OS package: %v", err)
		}
		ospkgFiles = append(ospkgFiles, f)
	case LocalStorage:
		ff, err := loadOSPackageFromLocalStorage()
		if err != nil {
			reboot("error loading OS package: %v", err)
		}
		ospkgFiles = append(ospkgFiles, ff...)
	default:
		reboot("unknown boot mode: %s", sc.BootMode.string())
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
			markInvalid(path)
			continue
		}

		//////////////////////////////////////////
		// Validate OS package's root certificates
		//////////////////////////////////////////
		fp := calculateFingerprint(ospkg.RootCertPEM)
		info("Fingerprint of OS package's root certificate:")
		info(fp)
		if !fingerprintIsValid(fp, sc.Fingerprints) {
			debug("Root certificate of OS package does not match expacted fingerprint")
			markInvalid(path)
			continue
		}
		info("OK!")

		////////////////////
		// Verify OS package
		////////////////////
		if *doDebug {
			str, _ := json.MarshalIndent(ospkg.Manifest, "", "  ")
			info("OS package manifest: %s", str)
		} else {
			info("Label: %s", ospkg.Manifest.Label)
		}

		n, valid, err := ospkg.Verify()
		if err != nil {
			debug("Error verifying OS package: %v", err)
			markInvalid(path)
			continue
		}
		if valid < sc.MinimalSignaturesMatch {
			debug("Not enough valid signatures: %d found, %d valid, %d required", n, valid, sc.MinimalSignaturesMatch)
			markInvalid(path)
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
			markInvalid(path)
			continue
		}

		markCurrent(path)
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

func markInvalid(file string) {
	if sc.BootMode == LocalStorage {
		// move invalid OS package to special directory
		invalid := filepath.Join(dataPartitionMountPoint, invalidDir, filepath.Base(file))
		if err := stboot.CreateAndCopy(file, invalid); err != nil {
			reboot("failed to move invalid OS package: %v", err)
		}
		if err := os.Remove(file); err != nil {
			reboot("failed to move invalid OS package: %v", err)
		}
	}
}

func markCurrent(file string) {
	if sc.BootMode == LocalStorage {
		// move current OS package to special file
		f := filepath.Join(dataPartitionMountPoint, currentOSPkgFile)
		rel, err := filepath.Rel(filepath.Dir(f), file)
		if err != nil {
			reboot("failed to indicate current OS package: %v", err)
		}
		if err = ioutil.WriteFile(f, []byte(rel), os.ModePerm); err != nil {
			reboot("failed to indicate current OS package: %v", err)
		}
	}
}

func loadOSPackageFromNetwork() (string, error) {
	if err := forceHTTPS(hc.ProvisioningURLs); err != nil {
		return "", fmt.Errorf("provisioning server URLs: %v", err)
	}

	info("Try downloading individual OS package")
	hwAddr, err := hostHWAddr()
	if err != nil {
		return "", fmt.Errorf("cannot evaluate hardware address: %v", err)
	}
	info("Host's HW address: %s", hwAddr.String())
	prefix := stboot.ComposeIndividualOSPackagePrefix(hwAddr)
	file := prefix + stboot.DefaultOSPackageName
	dest, err := tryDownload(hc.ProvisioningURLs, file)
	if err != nil {
		debug("%v", err)
		info("Try downloading general OS package")
		dest, err = tryDownload(hc.ProvisioningURLs, stboot.DefaultOSPackageName)
		if err != nil {
			debug("%v", err)
			return "", fmt.Errorf("cannot get appropriate OS package from provisioning servers")
		}
	}

	return dest, nil
}

func loadOSPackageFromLocalStorage() ([]string, error) {
	var ospkgs []string
	var newPkgs []string
	var knownGoodPkgs []string

	//new OS packages
	dir := filepath.Join(dataPartitionMountPoint, newDir)
	newPkgs, err := searchOSPackageFiles(dir)
	if err != nil {
		return nil, err
	}
	ospkgs = append(ospkgs, newPkgs...)

	// known good OS packages
	dir = filepath.Join(dataPartitionMountPoint, knownGoodDir)
	knownGoodPkgs, err = searchOSPackageFiles(dir)
	if err != nil {
		return nil, err
	}
	ospkgs = append(ospkgs, knownGoodPkgs...)
	return ospkgs, nil
}

func searchOSPackageFiles(dir string) ([]string, error) {
	var ret []string
	fis, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, fi := range fis {
		// take *.zip files only
		if filepath.Ext(fi.Name()) == ".zip" {
			b := filepath.Join(dir, fi.Name())
			ret = append(ret, b)
		}
	}
	// reverse order
	for i := 0; i < len(ret)/2; i++ {
		j := len(ret) - i - 1
		ret[i], ret[j] = ret[j], ret[i]
	}
	return ret, nil
}

// fingerprintIsValid returns true if fpHex is equal to on of
// those in expectedHex.
func fingerprintIsValid(fpHex string, expectedHex []string) bool {
	if len(expectedHex) == 0 {
		return false
	}
	for _, f := range expectedHex {
		f = strings.TrimSpace(f)
		if fpHex == f {
			return true
		}
	}
	return false
}

// calculateFingerprint returns the SHA256 checksum of the
// provided certificate.
func calculateFingerprint(pemBytes []byte) string {
	block, _ := pem.Decode(pemBytes)
	fp := sha256.Sum256(block.Bytes)
	str := hex.EncodeToString(fp[:])
	return strings.TrimSpace(str)
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
