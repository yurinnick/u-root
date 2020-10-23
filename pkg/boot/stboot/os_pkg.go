// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stboot

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/boot/multiboot"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/u-root/u-root/pkg/uzip"
)

const (
	bootfilesDir  string = "boot"
	acmDir        string = "boot/acms"
	signaturesDir string = "signatures"
	rootCertPath  string = "signatures/root.cert"
)

// OSPackage contains data to operate on the system transparency
// OSPackage archive. There is an underlying temporary directory
// representing the extracted archive.
type OSPackage struct {
	Archive           string
	Dir               string
	Manifest          *OSManifest
	FilesToBeMeasured []string
	RootCertPEM       []byte
	Signatures        []Signature
	NumSignatures     int
	HashValue         []byte
	Signer            Signer
}

// OSPackageFromArchive constructs a OSPackage from a zip file at archive.
func OSPackageFromArchive(archive string) (*OSPackage, error) {
	var ospkg = &OSPackage{}

	if _, err := os.Stat(archive); err != nil {
		return nil, fmt.Errorf("OSPackage: %v", err)
	}

	dir, err := ioutil.TempDir("", "os-package")
	if err != nil {
		return nil, fmt.Errorf("OSPackage: cannot create tmp dir: %v", err)
	}

	err = uzip.FromZip(archive, dir)
	if err != nil {
		return nil, fmt.Errorf("OSPackage: cannot unzip %s: %v", archive, err)
	}

	m, err := OSManifestFromFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, fmt.Errorf("OSPackage: getting configuration faild: %v", err)
	}
	if err = m.Validate(); err != nil {
		return nil, fmt.Errorf("OSPackage: invalid config: %v", err)
	}

	ospkg.Archive = archive
	ospkg.Dir = dir
	ospkg.Manifest = m

	err = ospkg.init()
	if err != nil {
		return ospkg, err
	}

	return ospkg, nil
}

// InitOSPackage constructs a OSPackage from the parsed files. The underlying
// tmporary directory is created with standardized paths and names.
func InitOSPackage(outDir, label, kernel, initramfs, cmdline, tboot, tbootArgs, rootCert string, acms []string, allowNonTXT bool) (*OSPackage, error) {
	var ospkg = &OSPackage{}

	t := time.Now()
	tstr := fmt.Sprintf("%04d-%02d-%02d-%02d-%02d-%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	name := "os-pkg-" + tstr + OSPackageExt
	ospkg.Archive = filepath.Join(outDir, name)

	dir, m, err := createFileTree(kernel, initramfs, tboot, rootCert, acms)
	if err != nil {
		return nil, fmt.Errorf("OSPackage: creating standard file tree faild: %v", err)
	}

	m.Label = label
	m.Cmdline = cmdline
	m.AllowNonTXT = allowNonTXT
	m.Write(dir)

	ospkg.Dir = dir
	ospkg.Manifest = &m

	err = ospkg.init()
	if err != nil {
		return nil, err
	}

	return ospkg, nil
}

func (ospkg *OSPackage) init() error {
	certPEM, err := ioutil.ReadFile(filepath.Join(ospkg.Dir, rootCertPath))
	if err != nil {
		return fmt.Errorf("OSPackage: reading root certificate faild: %v", err)
	}
	ospkg.RootCertPEM = certPEM

	err = ospkg.getFilesToBeHashed()
	if err != nil {
		return fmt.Errorf("OSPackage: collecting files for measurement failed: %v", err)
	}

	ospkg.Signer = Sha512PssSigner{}

	err = ospkg.getSignatures()
	if err != nil {
		return fmt.Errorf("OSPackage: getting signatures: %v", err)
	}

	ospkg.NumSignatures = len(ospkg.Signatures)
	return nil
}

// Clean removes the underlying temporary directory.
func (ospkg *OSPackage) Clean() error {
	err := os.RemoveAll(ospkg.Dir)
	if err != nil {
		return err
	}
	ospkg.Dir = ""
	return nil
}

// Pack archives the all contents of the underlying temporary
// directory using zip.
func (ospkg *OSPackage) Pack() error {
	if ospkg.Archive == "" {
		return errors.New("Booospkg.Archive is not set")
	}
	if ospkg.Dir == "" {
		return errors.New("Cannot locate underlying directory")
	}
	return uzip.ToZip(ospkg.Dir, ospkg.Archive)
}

// Hash calculates hashes of all boot configurations in OSPackage using the
// OSPackage.Signer's hash function.
func (ospkg *OSPackage) Hash() error {
	hash, err := ospkg.Signer.Hash(ospkg.FilesToBeMeasured...)
	if err != nil {
		return err
	}
	ospkg.HashValue = hash
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

	buf, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	cert, err := parseCertificate(buf)
	if err != nil {
		return err
	}

	err = validateCertificate(cert, ospkg.RootCertPEM)
	if err != nil {
		return err
	}

	if ospkg.HashValue == nil {
		err = ospkg.Hash()
		if err != nil {
			return err
		}
	}

	// check for dublicate certificates
	for _, sig := range ospkg.Signatures {
		if sig.Cert.Equal(cert) {
			return fmt.Errorf("certificate has already been used: %v", certFile)
		}
	}
	// sign with private key
	s, err := ospkg.Signer.Sign(privKeyFile, ospkg.HashValue)
	if err != nil {
		return err
	}
	sig := Signature{
		Bytes: s,
		Cert:  cert}
	// check certificate's public key
	err = ospkg.Signer.Verify(sig, ospkg.HashValue)
	if err != nil {
		return fmt.Errorf("public key in %s does not match the private key %s", filepath.Base(certFile), filepath.Base(privKeyFile))
	}
	// save
	ospkg.Signatures = append(ospkg.Signatures, sig)
	dir := filepath.Join(ospkg.Dir, signaturesDir)
	if err = sig.Write(dir); err != nil {
		return err
	}

	ospkg.NumSignatures++
	return nil
}

// Verify first validates the certificates stored together with the signatures
// and the verifies the signatures. The number of found signatures and the
// number of valid signatures are returned. A signature is valid if:
// * Its certificate was signed by ospkgs's root certificate
// * Verification is passed
// * No previous signature has the same certificate
func (ospkg *OSPackage) Verify() (found, verified int, err error) {
	if ospkg.HashValue == nil {
		err := ospkg.Hash()
		if err != nil {
			return 0, 0, err
		}
	}

	found = 0
	verified = 0
	var certsUsed []*x509.Certificate
	for i, sig := range ospkg.Signatures {
		found++
		err := validateCertificate(sig.Cert, ospkg.RootCertPEM)
		if err != nil {
			log.Printf("skip signature %d: invalid certificate: %v", i+1, err)
			continue
		}
		var dublicate bool
		for _, c := range certsUsed {
			if c.Equal(sig.Cert) {
				dublicate = true
				break
			}
		}
		if dublicate {
			log.Printf("skip signature %d: dublicate", i+1)
			continue
		}
		certsUsed = append(certsUsed, sig.Cert)
		err = ospkg.Signer.Verify(sig, ospkg.HashValue)
		if err != nil {
			log.Printf("skip signature %d: verification failed: %v", i+1, err)
			continue
		}
		verified++
	}
	return found, verified, nil
}

// OSImage retunrns a boot.OSImage generated from ospkg's configuration
func (ospkg *OSPackage) OSImage(txt bool) (boot.OSImage, error) {
	err := ospkg.Manifest.Validate()
	if err != nil {
		return nil, err
	}

	if txt && ospkg.Manifest.Tboot == "" {
		return nil, errors.New("OSPackage does not contain a TXT-ready configuration")
	}

	if !txt && !ospkg.Manifest.AllowNonTXT {
		return nil, errors.New("OSPackage requires the use of TXT")
	}

	var osi boot.OSImage
	if !txt {
		osi = &boot.LinuxImage{
			Name:    ospkg.Manifest.Label,
			Kernel:  uio.NewLazyFile(filepath.Join(ospkg.Dir, ospkg.Manifest.Kernel)),
			Initrd:  uio.NewLazyFile(filepath.Join(ospkg.Dir, ospkg.Manifest.Initramfs)),
			Cmdline: ospkg.Manifest.Cmdline,
		}
		return osi, nil
	}

	var modules []multiboot.Module
	kernel := multiboot.Module{
		Module:  uio.NewLazyFile(filepath.Join(ospkg.Dir, ospkg.Manifest.Kernel)),
		Cmdline: "OS-Kernel " + ospkg.Manifest.Cmdline,
	}
	modules = append(modules, kernel)

	initramfs := multiboot.Module{
		Module:  uio.NewLazyFile(filepath.Join(ospkg.Dir, ospkg.Manifest.Initramfs)),
		Cmdline: "OS-Initramfs",
	}
	modules = append(modules, initramfs)

	for n, a := range ospkg.Manifest.ACMs {
		acm := multiboot.Module{
			Module:  uio.NewLazyFile(filepath.Join(ospkg.Dir, a)),
			Cmdline: fmt.Sprintf("ACM%d", n+1),
		}
		modules = append(modules, acm)
	}

	osi = &boot.MultibootImage{
		Name:    ospkg.Manifest.Label,
		Kernel:  uio.NewLazyFile(filepath.Join(ospkg.Dir, ospkg.Manifest.Tboot)),
		Cmdline: ospkg.Manifest.TbootArgs,
		Modules: modules,
	}
	return osi, nil
}

// getFilesToBeHashed evaluates the paths of the OSPackage' files that are
// supposed to be hashed for signing and varifiaction. These are:
// * manifest.json
// * root.cert
// * files defined in manifest.json if they are present
func (ospkg *OSPackage) getFilesToBeHashed() error {
	var f []string

	// these files must be present
	config := filepath.Join(ospkg.Dir, ManifestName)
	kernel := filepath.Join(ospkg.Dir, ospkg.Manifest.Kernel)
	rootCert := filepath.Join(ospkg.Dir, rootCertPath)
	_, err := os.Stat(config)
	if err != nil {
		return errors.New("files to be measured: missing manifest.json")
	}
	_, err = os.Stat(kernel)
	if err != nil {
		return errors.New("files to be measured: missing kernel")
	}
	_, err = os.Stat(rootCert)
	if err != nil {
		return errors.New("files to be measured: missing root certificate")
	}
	f = append(f, config, kernel, rootCert)

	// following files are measured if present
	if ospkg.Manifest.Initramfs != "" {
		initramfs := filepath.Join(ospkg.Dir, ospkg.Manifest.Initramfs)
		_, err = os.Stat(initramfs)
		if err == nil {
			f = append(f, initramfs)
		}
	}
	if ospkg.Manifest.Tboot != "" {
		tboot := filepath.Join(ospkg.Dir, ospkg.Manifest.Tboot)
		_, err = os.Stat(tboot)
		if err == nil {
			f = append(f, tboot)
		}
	}
	for _, acm := range ospkg.Manifest.ACMs {
		a := filepath.Join(ospkg.Dir, acm)
		_, err = os.Stat(a)
		if err == nil {
			f = append(f, a)
		}
	}

	ospkg.FilesToBeMeasured = f
	return nil
}

// getSignatures initializes ospkg.signatures with the corresponding signatures
// and certificates found in the signatures folder of ospkg's underlying tmpDir.
// An error is returned if one of the files cannot be read or parsed.
func (ospkg *OSPackage) getSignatures() error {
	root := filepath.Join(ospkg.Dir, signaturesDir)

	sigs := make([]Signature, 0)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		ext := filepath.Ext(info.Name())

		if !info.IsDir() && (ext == ".signature") {
			sigBytes, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			certFile := strings.TrimSuffix(path, filepath.Ext(path)) + ".cert"
			certBytes, err := ioutil.ReadFile(certFile)
			if err != nil {
				return err
			}

			cert, err := parseCertificate(certBytes)
			if err != nil {
				return err
			}

			sig := Signature{
				Bytes: sigBytes,
				Cert:  cert,
			}
			sigs = append(sigs, sig)
			ospkg.Signatures = sigs
		}
		return nil
	})
	return err
}

// createFileTree copies the provided files to a well known tree inside
// the OSPackage's underlying tmpDir. The created tmpDir and a manifest
// initialized with corresponding paths is retruned.
func createFileTree(kernel, initramfs, tboot, rootCert string, acms []string) (dir string, m OSManifest, err error) {
	dir, err = ioutil.TempDir(os.TempDir(), "os-package")
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()

	var dst, rel string

	// Kernel
	if kernel == "" {
		err = errors.New("kernel missing")
	}
	rel = filepath.Join(bootfilesDir, filepath.Base(kernel))
	dst = filepath.Join(dir, rel)
	if err = CreateAndCopy(kernel, dst); err != nil {
		return
	}
	m.Kernel = rel

	// Initramfs
	if initramfs != "" {
		rel = filepath.Join(bootfilesDir, filepath.Base(initramfs))
		dst = filepath.Join(dir, rel)
		if err = CreateAndCopy(initramfs, dst); err != nil {
			return
		}
		m.Initramfs = rel
	}

	// tboot
	if tboot != "" {
		rel = filepath.Join(bootfilesDir, filepath.Base(tboot))
		dst = filepath.Join(dir, rel)
		if err = CreateAndCopy(tboot, dst); err != nil {
			return
		}
		m.Tboot = rel
	}

	// Root Certificate
	if rootCert == "" {
		err = errors.New("root certificate missing")
	}
	dst = filepath.Join(dir, rootCertPath)
	if err = CreateAndCopy(rootCert, dst); err != nil {
		return
	}

	// ACMs
	if len(acms) > 0 {
		for _, acm := range acms {
			rel = filepath.Join(acmDir, filepath.Base(acm))
			dst = filepath.Join(dir, rel)
			if err = CreateAndCopy(acm, dst); err != nil {
				return
			}
			m.ACMs = append(m.ACMs, rel)
		}
	}

	return
}

// CreateAndCopy copies the content of the file at src to dst. If dst does not
// exist it is created. In case case src does not exist, creation of dst
// or copying fails and error is returned.
func CreateAndCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err = os.MkdirAll(filepath.Dir(dst), os.ModePerm); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}
