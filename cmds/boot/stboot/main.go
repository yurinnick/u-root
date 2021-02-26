// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/boot/stboot"
	"github.com/u-root/u-root/pkg/recovery"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/u-root/u-root/pkg/ulog"
)

// Flags
var (
	doDebug = flag.Bool("debug", false, "Print additional debug output")
	klog    = flag.Bool("klog", false, "Print output to all attached consoles via the kernel log")
	dryRun  = flag.Bool("dryrun", false, "Do everything except booting the loaded kernel")
)

// Globals
var (
	debug          = func(string, ...interface{}) {}
	securityConfig SecurityConfig
	hostConfig     HostConfig
	httpsRoots     *x509.CertPool
	txtHostSuport  bool
)

// Files at initramfs
const (
	securityConfigFile = "/etc/security_configuration.json"
	signingRootFile    = "/etc/ospkg_signing_root.pem"
	httpsRootsFile     = "/etc/https_roots.pem"
)

// Files at STBOOT partition
const (
	hostConfigurationFile = "/host_configuration.json"
)

// Files at STDATA partition
const (
	timeFixFile        = "stboot/etc/system_time_fix"
	currentOSPkgFile   = "stboot/etc/current_ospkg_pathname"
	localOSPkgDir      = "stboot/os_pkgs/local/"
	localBootOrderFile = "stboot/os_pkgs/local/boot_order"
	networkOSpkgCache  = "stboot/os_pkgs/cache"
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

type ospkgSampl struct {
	name       string
	descriptor io.ReadCloser
	archive    io.ReadCloser
}

func main() {
	log.SetFlags(0) // no time or date
	log.SetPrefix("stboot: ")
	ulog.KernelLog.SetLogLevel(ulog.KLogNotice)
	ulog.KernelLog.SetConsoleLogLevel(ulog.KLogInfo)

	flag.Parse()
	if *doDebug {
		debug = info
	}

	info(banner)

	/////////////////////////
	// Early validation
	/////////////////////////

	// Security Configuration
	s, err := ioutil.ReadFile(securityConfigFile)
	if err != nil {
		reboot("missing security config: %v", err)
	}
	if err = json.Unmarshal(s, &securityConfig); err != nil {
		reboot("cannot parse security config: %v", err)
	}
	if *doDebug {
		str, _ := json.MarshalIndent(securityConfig, "", "  ")
		info("Security configuration: %s", str)
	}
	if err = securityConfig.Validate(); err != nil {
		reboot("invalid security config: %v", err)
	}

	// Signing root certificate
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

	// HTTPS root certificates
	httpsRoots = x509.NewCertPool()
	if securityConfig.BootMode == Network {
		pemBytes, err = ioutil.ReadFile(httpsRootsFile)
		if err != nil {
			reboot("loading https root certs failed: %v", err)
		}
		if ok := httpsRoots.AppendCertsFromPEM(pemBytes); !ok {
			reboot("parsing https root certs failed")
		}
	}

	// Mount STBOOT partition
	err = mountBootPartition()
	if err != nil {
		reboot("STBOOT partition: %v", err)
	}

	// Host configuration
	p := filepath.Join(bootPartitionMountPoint, hostConfigurationFile)
	bytes, err := ioutil.ReadFile(p)
	if err != nil {
		reboot("missing host config: %v", err)
	}
	err = json.Unmarshal(bytes, &hostConfig)
	if err != nil {
		reboot("cannot parse host config: %v", err)
	}
	if *doDebug {
		str, _ := json.MarshalIndent(hostConfig, "", "  ")
		info("Host configuration: %s", str)
	}
	if err = hostConfig.Validate(securityConfig.BootMode == Network); err != nil {
		reboot("invalid host config: %v", err)
	}

	// Mount STDATA partition
	err = mountDataPartition()
	if err != nil {
		reboot("STDATA partition: %v", err)
	}

	// System time
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

	// boot order
	var bootorder []string
	if securityConfig.BootMode == Local {
		p = filepath.Join(dataPartitionMountPoint, localBootOrderFile)
		f, err := os.Open(p)
		if err != nil {
			reboot("STDATA partition: missing file %s", localBootOrderFile)
		}

		names := make([]string, 0)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			names = append(names, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			reboot("scanning boot order file: %v", err)
		}
		f.Close()
		if len(names) == 0 {
			reboot("no boot order entries found")
		}

		for _, name := range names {
			ext := filepath.Ext(name)
			if ext == stboot.OSPackageExt || ext == stboot.DescriptorExt {
				name = strings.TrimSuffix(name, ext)
			}
			p := filepath.Join(dataPartitionMountPoint, localOSPkgDir, name+stboot.OSPackageExt)
			_, err := os.Stat(p)
			if err != nil {
				debug("skip %s: %v", name, err)
				continue
			}
			p = filepath.Join(dataPartitionMountPoint, localOSPkgDir, name+stboot.DescriptorExt)
			_, err = os.Stat(p)
			if err != nil {
				debug("skip %s: %v", name, err)
				continue
			}
			bootorder = append(bootorder, name)
		}
		if len(bootorder) == 0 {
			reboot("no valid boot order entries found")
		}
	}

	// directories at STDATA partition
	etcDir := filepath.Dir(currentOSPkgFile)
	p = filepath.Join(dataPartitionMountPoint, etcDir)
	stat, err := os.Stat(p)
	if err != nil || !stat.IsDir() {
		reboot("STDATA partition: missing directory %s", etcDir)
	}

	if securityConfig.BootMode == Local {
		p = filepath.Join(dataPartitionMountPoint, localOSPkgDir)
		stat, err := os.Stat(p)
		if err != nil || !stat.IsDir() {
			reboot("STDATA partition: missing directory %s", localOSPkgDir)
		}
	}

	if securityConfig.BootMode == Network {
		p = filepath.Join(dataPartitionMountPoint, networkOSpkgCache)
		stat, err := os.Stat(p)
		if err != nil || !stat.IsDir() {
			reboot("STDATA partition: missing directory %s", networkOSpkgCache)
		}
	}

	// network interface
	if securityConfig.BootMode == Network {
		switch hostConfig.NetworkMode {
		case Static:
			if err := configureStaticNetwork(); err != nil {
				reboot("cannot set up IO: %v", err)
			}
		case DHCP:
			if err := configureDHCPNetwork(); err != nil {
				reboot("cannot set up IO: %v", err)
			}
		default:
			reboot("unknown network mode: %s", hostConfig.NetworkMode.String())
		}
		if hostConfig.DNSServer != nil {
			info("set DNS Server %s", hostConfig.DNSServer.String())
			if err := setDNSServer(hostConfig.DNSServer); err != nil {
				reboot("set DNS Server: %v", err)
			}
		}
	}

	// TXT host support
	info("TXT self tests are not implementet yet.")
	txtHostSuport = false

	// Init RNG
	rngDev := "/dev/urandom"
	info("Writing seed to %s", rngDev)
	seed, err := hostConfig.ParseEntropySeed()
	if err != nil {
		reboot("parse entropy seed: %v", err)
	}
	if err := ioutil.WriteFile(rngDev, seed[:], 0); err != nil {
		reboot("failed to init RNG: %v", err)
	}

	//////////////////
	// Load OS package
	//////////////////
	var ospkgSampls []ospkgSampl

	switch securityConfig.BootMode {
	case Network:
		info("Loading OS package via network")
		s, err := networkLoad()
		if err != nil {
			reboot("load OS package via network: %v", err)
		}
		ospkgSampls = append(ospkgSampls, s)
	case Local:
		info("Loading OS package from disk")
		ss, err := diskLoad(bootorder)
		if err != nil {
			reboot("load OS package from disk: %v", err)
		}
		ospkgSampls = append(ospkgSampls, ss...)
	default:
		reboot("unsupported boot mode: %s", securityConfig.BootMode.String())
	}
	if len(ospkgSampls) == 0 {
		reboot("No OS packages found")
	}
	if *doDebug {
		info("OS packages to be processed:")
		for _, s := range ospkgSampls {
			info(" - %s", s.name)
		}
	}

	//////////////////////
	// Process OS packages
	//////////////////////
	var bootImg boot.OSImage
	var ospkg *stboot.OSPackage
	for _, sample := range ospkgSampls {
		info("Processing OS package %s", sample.name)
		aBytes, err := ioutil.ReadAll(sample.archive)
		if err != nil {
			debug("read archive: %v", err)
			continue
		}
		dBytes, err := ioutil.ReadAll(sample.descriptor)
		if err != nil {
			debug("read archive: %v", err)
			continue
		}
		ospkg, err = stboot.NewOSPackage(aBytes, dBytes)
		if err != nil {
			debug("create OS package: %v", err)
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
		threshold := securityConfig.MinimalSignaturesMatch
		if valid < threshold {
			debug("Not enough valid signatures: %d found, %d valid, %d required", n, valid, threshold)
			continue
		}

		debug("Signatures: %d found, %d valid, %d required", n, valid, threshold)
		info("OS package passed verification")
		info(check)

		/////////////
		// Extract OS
		/////////////
		bootImg, err = ospkg.OSImage(txtHostSuport)
		if err != nil {
			debug("get boot image: %v", err)
			continue
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
			debug("unknown boot image type %T", t)
			continue
		}

		if securityConfig.BootMode == Local {
			markCurrentOSpkg(sample.name)
		}
		break
	} // end process-os-pkgs-loop
	for _, s := range ospkgSampls {
		s.archive.Close()
		s.descriptor.Close()
	}
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
	securityConfigBytes, _ := json.Marshal(securityConfig)

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
	err = bootImg.Load(false)
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

func markCurrentOSpkg(name string) {
	f := filepath.Join(dataPartitionMountPoint, currentOSPkgFile)
	current := filepath.Join(dataPartitionMountPoint, localOSPkgDir, name)
	current = current + string('\n')
	if err := ioutil.WriteFile(f, []byte(current), os.ModePerm); err != nil {
		reboot("write current OS package: %v", err)
	}
}

func networkLoad() (ospkgSampl, error) {
	var sample ospkgSampl
	urls, err := hostConfig.ParseProvisioningURLs()
	if err != nil {
		return sample, fmt.Errorf("pars URLs: %v", err)
	}
	if *doDebug {
		info("Provisioning URLs:")
		for _, u := range urls {
			info(" - %s", u.String())
		}
	}

	for _, url := range urls {
		debug("downloading %s", url.String())
		dBytes, err := download(url)
		if err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		debug("parsing descriptor")
		descriptor, err := stboot.DescriptorFromBytes(dBytes)
		if err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		debug("validating descriptor")
		if err = descriptor.Validate(); err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		debug("parsing OS package URL form descriptor")
		if descriptor.PkgURL == "" {
			debug("Skip %s: no OS package URL provided in descriptor")
			continue
		}
		pkgURL, err := url.Parse(descriptor.PkgURL)
		if err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		s := pkgURL.Scheme
		if s == "" || s != "http" && s != "https" {
			debug("Skip %s: missing or unsupported scheme in OS package URL %s", pkgURL.String())
			continue
		}
		debug("downloading %s", pkgURL.String())
		aBytes, err := download(pkgURL)
		if err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		ar := uio.NewLazyOpener(func() (io.Reader, error) {
			return bytes.NewReader(aBytes), nil
		})
		dr := uio.NewLazyOpener(func() (io.Reader, error) {
			return bytes.NewReader(dBytes), nil
		})

		sample.name = url.String()
		sample.archive = ar
		sample.descriptor = dr
		return sample, nil
	}
	return sample, fmt.Errorf("all provisioning URLs failed")
}

func diskLoad(names []string) ([]ospkgSampl, error) {
	var samples = make([]ospkgSampl, 0)
	dir := filepath.Join(dataPartitionMountPoint, localOSPkgDir)
	if len(names) == 0 {
		return samples, fmt.Errorf("names must not be empty")
	}
	for _, name := range names {
		ap := filepath.Join(dir, name+stboot.OSPackageExt)
		dp := filepath.Join(dir, name+stboot.DescriptorExt)
		if _, err := os.Stat(ap); err != nil {
			return samples, err
		}
		if _, err := os.Stat(dp); err != nil {
			return samples, err
		}
		ar := uio.NewLazyOpener(func() (io.Reader, error) {
			return os.Open(ap)
		})
		dr := uio.NewLazyOpener(func() (io.Reader, error) {
			return os.Open(dp)
		})
		s := ospkgSampl{
			name:       name,
			archive:    ar,
			descriptor: dr,
		}
		samples = append(samples, s)
	}
	return samples, nil
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
