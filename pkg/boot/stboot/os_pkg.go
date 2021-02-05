// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stboot

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/boot/multiboot"
)

const (
	bootfilesDir  string = "boot"
	acmDir        string = "boot/acms"
	signaturesDir string = "signatures"
)

// OSPackage represents an OS package ZIP archive and and related data.
type OSPackage struct {
	Archive    string
	Raw        []byte
	Manifest   *OSManifest
	Kernel     []byte
	Initramfs  []byte
	Tboot      []byte
	ACMs       [][]byte
	Descriptor *Descriptor
	HashValue  [32]byte
	Signer     Signer
}

// InitOSPackage constructs a OSPackage from the passed files.
func InitOSPackage(out, label, pkgURL, kernel, initramfs, cmdline, tboot, tbootArgs string, acms []string) (*OSPackage, error) {
	var m = &OSManifest{
		Version:   ManifestVersion,
		Label:     label,
		Cmdline:   cmdline,
		TbootArgs: tbootArgs,
	}

	var d = &Descriptor{
		Version: DescriptorVersion,
		PkgURL:  pkgURL,
	}

	var ospkg = &OSPackage{
		Archive:    out,
		Manifest:   m,
		Descriptor: d,
		Signer:     ED25519Signer{},
	}

	ospkg.Kernel, _ = ioutil.ReadFile(kernel)
	if ospkg.Kernel != nil {
		ospkg.Manifest.KernelPath = filepath.Join(bootfilesDir, filepath.Base(kernel))
	}

	ospkg.Initramfs, _ = ioutil.ReadFile(initramfs)
	if ospkg.Initramfs != nil {
		ospkg.Manifest.InitramfsPath = filepath.Join(bootfilesDir, filepath.Base(initramfs))
	}

	ospkg.Tboot, _ = ioutil.ReadFile(tboot)
	if ospkg.Tboot != nil {
		ospkg.Manifest.TbootPath = filepath.Join(bootfilesDir, filepath.Base(tboot))
	}

	for _, acm := range acms {
		a, _ := ioutil.ReadFile(acm)
		if a != nil {
			ospkg.ACMs = append(ospkg.ACMs, a)
			name := filepath.Join(acmDir, filepath.Base(acm))
			ospkg.Manifest.ACMPaths = append(ospkg.Manifest.ACMPaths, name)
		}
	}

	if err := ospkg.Validate(); err != nil {
		return nil, err
	}

	return ospkg, nil
}

// OSPackageFromArchive opens a OSPackage. Either the path to the os package
// ZIP file or to the os package descriptor JSON file can be passed. Both
// files are expected to have the same name.
func OSPackageFromFile(name string) (*OSPackage, error) {
	ext := filepath.Ext(name)
	if ext != OSPackageExt && ext != DescriptorExt {
		return nil, fmt.Errorf("os package: invalid file extension %s", ext)
	}

	name = strings.TrimSuffix(name, ext)
	archivePath := name + OSPackageExt
	descriptorPath := name + DescriptorExt

	archiveBytes, err := ioutil.ReadFile(archivePath)
	if err != nil {
		return nil, fmt.Errorf("os package: opening archive failed: %v", err)
	}
	descriptorBytes, err := ioutil.ReadFile(descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("os package: opening descriptor failed: %v", err)
	}

	return OSPackageFromBytes(archiveBytes, descriptorBytes, archivePath)
}

// OSPackageFromArchive constructs a OSPackage from a zip file at archive.
func OSPackageFromBytes(archiveZIP, descriptorJSON []byte, archivePath string) (*OSPackage, error) {

	// descriptor
	descriptor, err := DescriptorFromBytes(descriptorJSON)
	if err != nil {
		if err != nil {
			return nil, fmt.Errorf("os package: %v", err)
		}
	}

	if err = descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("os package: invalid descriptor: %v", err)
	}

	ospkg := &OSPackage{
		Archive:    archivePath,
		Raw:        archiveZIP,
		Descriptor: descriptor,
		Signer:     ED25519Signer{},
	}

	ospkg.HashValue, err = calculateHash(ospkg.Raw)
	if err != nil {
		return nil, fmt.Errorf("os package: calculate hash failed: %v", err)
	}

	// open archive
	reader := bytes.NewReader(ospkg.Raw)
	size := int64(len(ospkg.Raw))
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, fmt.Errorf("os package: zip reader failed: %v", err)
	}

	// manifest
	m, err := unzipFile(archive, ManifestName)
	if err != nil {
		return nil, fmt.Errorf("os package: unzip failed: %v", err)
	}
	ospkg.Manifest, err = OSManifestFromBytes(m)
	if err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}

	if err = ospkg.Manifest.Validate(); err != nil {
		return nil, fmt.Errorf("os package: invalid manifest: %v", err)
	}

	// kernel
	ospkg.Kernel, err = unzipFile(archive, ospkg.Manifest.KernelPath)
	if err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}

	// initramfs
	ospkg.Initramfs, err = unzipFile(archive, ospkg.Manifest.InitramfsPath)
	if err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}

	// kernel
	ospkg.Tboot, err = unzipFile(archive, ospkg.Manifest.TbootPath)
	if err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}

	// ACMs
	if len(ospkg.Manifest.ACMPaths) > 0 {
		for _, acm := range ospkg.Manifest.ACMPaths {
			a, err := unzipFile(archive, acm)
			if err != nil {
				return nil, fmt.Errorf("os package: %v", err)
			}
			ospkg.ACMs = append(ospkg.ACMs, a)
		}
	}

	return ospkg, nil
}

func (ospkg *OSPackage) Validate() error {
	// Archive path
	if ospkg.Archive == "" {
		return fmt.Errorf("os package: missing archive path")
	} else if filepath.Ext(ospkg.Archive) != OSPackageExt {
		return fmt.Errorf("os package: archive path must end with .zip extension")
	}

	// Manifest
	if ospkg.Manifest == nil {
		return fmt.Errorf("os package: missing manifest data")
	} else if err := ospkg.Manifest.Validate(); err != nil {
		return fmt.Errorf("os package: %v", err)
	}

	// Descriptor
	if ospkg.Descriptor == nil {
		return fmt.Errorf("os package: missing descriptor data")
	} else if err := ospkg.Descriptor.Validate(); err != nil {
		return fmt.Errorf("os package: %v", err)
	}

	// Kernel
	if len(ospkg.Kernel) == 0 {
		return fmt.Errorf("os package: missing kernel")
	}

	return nil
}

// Pack archives the contents of ospkg using zip.
func (ospkg *OSPackage) Pack() error {
	zipfile, err := os.Create(ospkg.Archive)
	if err != nil {
		return fmt.Errorf("os package: creating ZIP failed: %v", err)
	}
	defer zipfile.Close()

	archive := zip.NewWriter(zipfile)
	defer archive.Close()

	// directories
	if err = zipDir(archive, bootfilesDir); err != nil {
		return fmt.Errorf("os package: creating dir failed: %v", err)
	}
	if len(ospkg.ACMs) > 0 {
		if err = zipDir(archive, acmDir); err != nil {
			return fmt.Errorf("os package: creating dir failed: %v", err)
		}
	}

	// kernel
	name := ospkg.Manifest.KernelPath
	if err := zipFile(archive, name, ospkg.Kernel); err != nil {
		return fmt.Errorf("OS package: writing kernel failed: %v", err)
	}

	// initramfs
	if len(ospkg.Initramfs) > 0 {
		name = ospkg.Manifest.InitramfsPath
		if err := zipFile(archive, name, ospkg.Initramfs); err != nil {
			return fmt.Errorf("OS package: writing initramfs failed: %v", err)
		}
	}

	// tboot
	if len(ospkg.Tboot) > 0 {
		name = ospkg.Manifest.TbootPath
		if err := zipFile(archive, name, ospkg.Tboot); err != nil {
			return fmt.Errorf("OS package: writing tboot failed: %v", err)
		}
	}

	// ACMs
	if len(ospkg.ACMs) > 0 {
		for i, acm := range ospkg.ACMs {
			name = ospkg.Manifest.ACMPaths[i]
			if err := zipFile(archive, name, acm); err != nil {
				return fmt.Errorf("OS package: writing ACMs failed: %v", err)
			}
		}
	}

	// manifest
	mbytes, err := ospkg.Manifest.Bytes()
	if err != nil {
		return fmt.Errorf("OS package: serializing manifest failed: %v", err)
	}
	if err := zipFile(archive, ManifestName, mbytes); err != nil {
		return fmt.Errorf("OS package: writing manifest failed: %v", err)
	}

	// descriptor
	dbytes, err := ospkg.Descriptor.Bytes()
	if err != nil {
		return fmt.Errorf("OS package: serializing descriptor failed: %v", err)
	}
	name = strings.Replace(ospkg.Archive, filepath.Ext(ospkg.Archive), DescriptorExt, -1)

	if err = ioutil.WriteFile(name, dbytes, 0666); err != nil {
		return fmt.Errorf("OS package: writing descriptor file failed: %v", err)
	}

	return nil
}

// Sign signes ospkg.HashValue using ospkg.Signer with the private key named by
// privKeyFile. The certificate named by certFile is supposed to correspond
// to the private key. Both, the signature and the certificate are stored into
// the OSPackage.
func (ospkg *OSPackage) Sign(privKeyFile, certFile string) error {
	if _, err := os.Stat(privKeyFile); err != nil {
		return err
	}

	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	cert, err := parseCertificate(certBytes)
	if err != nil {
		return err
	}

	ospkg.HashValue, err = calculateHash(ospkg.Raw)
	if err != nil {
		return err
	}

	// check for dublicate certificates
	for _, certBytes := range ospkg.Descriptor.Certificates {
		storedCert, err := parseCertificate(certBytes)
		if err != nil {
			return err
		}
		if storedCert.Equal(cert) {
			return fmt.Errorf("certificate has already been used: %v", certFile)
		}
	}

	// sign with private key
	sig, err := ospkg.Signer.Sign(privKeyFile, ospkg.HashValue[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}

	ospkg.Descriptor.Certificates = append(ospkg.Descriptor.Certificates, certBytes)
	ospkg.Descriptor.Signatures = append(ospkg.Descriptor.Signatures, sig)
	return nil
}

// Verify first validates the certificates stored together with the signatures
// in the os package descriptor against the provided root certificate and then
// verifies the signatures.
// The number of found signatures and the number of valid signatures are returned.
// A signature is valid if:
// * Its certificate was signed by the root certificate
// * It passed verification
// * Its certificate is not a duplicate of a previous one
func (ospkg *OSPackage) Verify(rootCertPEM []byte) (found, valid int, err error) {
	found = 0
	valid = 0
	var certsUsed []*x509.Certificate
	for i, sig := range ospkg.Descriptor.Signatures {
		found++
		cert, err := parseCertificate(ospkg.Descriptor.Certificates[i])
		if err != nil {
			return 0, 0, fmt.Errorf("verify: certificate %d: parsing failed: %v", i, err)
		}
		err = ValidateCertificate(cert, rootCertPEM)
		if err != nil {
			log.Printf("skip signature %d: invalid certificate: %v", i+1, err)
			continue
		}
		var dublicate bool
		for _, c := range certsUsed {
			if c.Equal(cert) {
				dublicate = true
				break
			}
		}
		if dublicate {
			log.Printf("skip signature %d: dublicate", i+1)
			continue
		}
		certsUsed = append(certsUsed, cert)
		err = ospkg.Signer.Verify(sig, ospkg.HashValue[:], cert)
		if err != nil {
			log.Printf("skip signature %d: verification failed: %v", i+1, err)
			continue
		}
		valid++
	}
	return found, valid, nil
}

// OSImage retunrns a boot.OSImage generated from ospkg's configuration
func (ospkg *OSPackage) OSImage(txt bool) (boot.OSImage, error) {
	err := ospkg.Manifest.Validate()
	if err != nil {
		return nil, err
	}

	if txt && ospkg.Manifest.TbootPath == "" {
		return nil, errors.New("OSPackage does not contain a TXT-ready configuration")
	}

	var osi boot.OSImage
	if !txt {
		osi = &boot.LinuxImage{
			Name:    ospkg.Manifest.Label,
			Kernel:  bytes.NewReader(ospkg.Kernel),
			Initrd:  bytes.NewReader(ospkg.Initramfs),
			Cmdline: ospkg.Manifest.Cmdline,
		}
		return osi, nil
	}

	var modules []multiboot.Module
	kernel := multiboot.Module{
		Module:  bytes.NewReader(ospkg.Kernel),
		Cmdline: "OS-Kernel " + ospkg.Manifest.Cmdline,
	}
	modules = append(modules, kernel)

	initramfs := multiboot.Module{
		Module:  bytes.NewReader(ospkg.Initramfs),
		Cmdline: "OS-Initramfs",
	}
	modules = append(modules, initramfs)

	for n, a := range ospkg.ACMs {
		acm := multiboot.Module{
			Module:  bytes.NewReader(a),
			Cmdline: fmt.Sprintf("ACM%d", n+1),
		}
		modules = append(modules, acm)
	}

	osi = &boot.MultibootImage{
		Name:    ospkg.Manifest.Label,
		Kernel:  bytes.NewReader(ospkg.Tboot),
		Cmdline: ospkg.Manifest.TbootArgs,
		Modules: modules,
	}
	return osi, nil
}

func zipDir(archive *zip.Writer, name string) error {
	if name[len(name)-1:] != "/" {
		name += "/"
	}
	_, err := archive.Create(name)
	return err
}

func zipFile(archive *zip.Writer, name string, src []byte) error {
	f, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewReader(src))
	return err
}

func unzipFile(archive *zip.Reader, name string) ([]byte, error) {
	for _, file := range archive.File {
		if file.Name == name {
			f, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("cannot open %s in archive: %v", name, err)
			}

			buf := new(bytes.Buffer)
			if _, err = io.Copy(buf, f); err != nil {
				return nil, fmt.Errorf("reading %s failed: %v", name, err)
			}
			return buf.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("cannot find %s in archive", name)
}

func calculateHash(data []byte) ([32]byte, error) {
	if len(data) == 0 {
		return [32]byte{}, fmt.Errorf("empty input")
	}
	return sha256.Sum256(data), nil
}
