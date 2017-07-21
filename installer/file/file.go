/*
Copyright 2017 Luke Granger-Brown

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package file installs certificates into flat files on disk.
package file // import "lukegb.com/encryptomatic/installer/file"

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/viper"

	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/encryptoutil"
)

const (
	publicFileMode  os.FileMode = 0666
	privateFileMode os.FileMode = 0600
)

func init() {
	encryptomatic.RegisterInstaller("file", New)
}

func New(v *viper.Viper) (encryptomatic.Installer, error) {
	i := &Installer{}
	err := v.Unmarshal(i)
	if err != nil {
		return nil, err
	}
	return i, nil
}

// Installer writes certificates to files on disk in various formats.
type Installer struct {
	// FullChain is the path on disk to write the entire certificate chain to, including the leaf certificate and any intermediates provided by the server.
	// If empty, no file will be written.
	FullChain string `mapstructure:"full_chain"`

	// Chain is the path to write the certificate chain to, not including the end entity certificate.
	// If empty, no file will be written.
	Chain string `mapstructure:"chain"`

	// EndEntity is the path on disk to write the certificate to.
	// If empty, no file will be written.
	EndEntity string `mapstructure:"end_entity"`

	// FullPrivateChain is the path on disk to write a bundle to, in a format suitable for HAProxy. This is FullChain with PrivateKey concatenated.
	// If empty, no file will be written.
	FullPrivateChain string `mapstructure:"full_private_chain"`

	// PrivateKey is the path on disk to write the private key to.
	// If empty, no file will be written.
	// If CertificateRequest is populated, this field is ignored and no file will be written.
	PrivateKey string `mapstructure:"private_key"`

	// If this flag is true, private keys will be written with 0666 (before umask), rather than 0600.
	// Set at your own risk.
	InsecurePrivateKey bool `mapstructure:"insecure_private_key"`

	// CertificateRequest is the path on disk to read a certificate request from.
	// If empty, a certificate request and private key will be automatically generated.
	CertificateRequest string `mapstructure:"certificate_request"`

	// BeforeCmd is a command to execute before writing the new certificate.
	// If empty, no command will be run.
	BeforeCmd []string `mapstructure:"before_cmd"`

	// AfterCmd is a command to execute after writing the new certificate.
	// If empty, no command will be run.
	AfterCmd []string `mapstructure:"after_cmd"`
}

func runCmd(ctx context.Context, cmd []string) error {
	if len(cmd) == 0 {
		return nil
	}

	log.Printf("file: running command %v", cmd)
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	if err := c.Run(); err != nil {
		log.Printf("file: %v failed: %v", cmd, err)
	}
	log.Printf("file: command completed")
	return nil
}

// GenerateCSR reads a CSR off disk, if one has been provided.
func (i *Installer) GenerateCSR(ctx context.Context) (*x509.CertificateRequest, error) {
	if i.CertificateRequest == "" {
		// No CertificateRequest, request generation.
		log.Printf("file: no CertificateRequest, requesting generation of CSR")
		return nil, nil
	}

	log.Printf("file: loading CSR from %v", i.CertificateRequest)
	f, err := os.Open(i.CertificateRequest)
	if err != nil {
		return nil, fmt.Errorf("file: failed to open %q: %v", i.CertificateRequest, err)
	}
	defer f.Close()

	fbytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("file: failed to read %q: %v", i.CertificateRequest, err)
	}

	csrBlock, _ := pem.Decode(fbytes)
	if csrBlock == nil {
		return nil, fmt.Errorf("file: CSR is badly formatted")
	}

	return x509.ParseCertificateRequest(csrBlock.Bytes)
}

func writeOut(x []byte, fs []io.Writer) error {
	for _, f := range fs {
		if f == nil {
			continue
		}

		// Note that io.Writer, unlike io.Reader, is not permitted to perform partial I/O without error.
		_, err := f.Write(x)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetCertificate retrieves the current certificate from disk, or nil if none exists.
func (i *Installer) GetCertificate(ctx context.Context) (*x509.Certificate, error) {
	log.Printf("file: inside GetCertificate")

	candidatePaths := []string{i.FullChain, i.EndEntity, i.FullPrivateChain}
	for _, p := range candidatePaths {
		if p == "" {
			continue
		}
		log.Printf("file: checking for existing certificate at %v", p)
		f, err := os.Open(p)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("file: failed to open %v: %v", p, err)
		}
		defer f.Close()

		pemBytes, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("file: couldn't read %v: %v", p, err)
		}

		cert, _, err := encryptoutil.PEMToCertificate(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("file: %v contains garbage: %v", p, err)
		}
		log.Printf("file: found certificate at %v", p)
		return cert, nil
	}

	return nil, nil
}

// SetCertificate installs the provided certificate into the provided files.
func (i *Installer) SetCertificate(ctx context.Context, caBundle []*x509.Certificate, cert *x509.Certificate, pkey crypto.PrivateKey) (err error) {
	log.Printf("file: inside SetCertificate")
	if err = runCmd(ctx, i.BeforeCmd); err != nil {
		return fmt.Errorf("file: failed to run BeforeCmd %v: %v", i.BeforeCmd, err)
	}

	privateKeyMode := privateFileMode
	if i.InsecurePrivateKey {
		privateKeyMode = publicFileMode
	}

	// Open *all* the files
	type handles struct {
		FullChain        io.WriteCloser
		Chain            io.WriteCloser
		EndEntity        io.WriteCloser
		FullPrivateChain io.WriteCloser
		PrivateKey       io.WriteCloser
	}
	type pair struct {
		fn   string
		out  *io.WriteCloser
		mode os.FileMode
	}
	var h handles
	for _, p := range []pair{
		pair{i.FullChain, &h.FullChain, publicFileMode},
		pair{i.Chain, &h.Chain, publicFileMode},
		pair{i.EndEntity, &h.EndEntity, publicFileMode},
		pair{i.FullPrivateChain, &h.FullPrivateChain, privateKeyMode},
		pair{i.PrivateKey, &h.PrivateKey, privateKeyMode},
	} {
		if p.fn == "" {
			continue
		}
		log.Printf("file: opening %s", p.fn)
		f, err := os.OpenFile(p.fn, os.O_RDWR|os.O_CREATE|os.O_TRUNC, p.mode)
		if err != nil {
			return fmt.Errorf("file: failed to create %q: %v", p.fn, err)
		}
		*p.out = f
		defer func(f io.Closer) {
			ferr := f.Close()
			if err == nil {
				err = ferr
			}
		}(*p.out)
	}

	// We write in the following order, so that the composite files are in the correct order:
	// 1. End Entity
	log.Printf("file: writing end entity certificate")
	if err := writeOut(encryptoutil.CertificateToPEM(cert), []io.Writer{h.FullChain, h.EndEntity, h.FullPrivateChain}); err != nil {
		return fmt.Errorf("file: failed to write end entity certificate: %v", err)
	}

	// 2. Intermediates
	log.Printf("file: writing certificate bundle")
	for _, ca := range caBundle {
		if err := writeOut(encryptoutil.CertificateToPEM(ca), []io.Writer{h.FullChain, h.Chain, h.FullPrivateChain}); err != nil {
			return fmt.Errorf("file: failed to write intermediate certificate: %v", err)
		}
	}

	// 3. Private Key
	log.Printf("file: writing private key")
	pkeyBytes, err := encryptoutil.PrivateKeyToPEM(pkey)
	if err != nil {
		return fmt.Errorf("file: failed to serialize private key: %v", err)
	}
	if err := writeOut(pkeyBytes, []io.Writer{h.FullPrivateChain, h.PrivateKey}); err != nil {
		return fmt.Errorf("file: failed to write private key: %v", err)
	}

	if err = runCmd(ctx, i.AfterCmd); err != nil {
		return fmt.Errorf("file: failed to run AfterCmd %v: %v", i.AfterCmd, err)
	}

	return nil
}
