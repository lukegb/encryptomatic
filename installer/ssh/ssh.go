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

// Package ssh installs certificates into flat files on a remote host, using SSH/SCP.
package ssh

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/sftp"
	"github.com/spf13/viper"

	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/encryptoutil"
)

const (
	publicFileMode  os.FileMode = 0666
	privateFileMode os.FileMode = 0600
)

func init() {
	encryptomatic.RegisterInstaller("ssh", New)
}

func New(v *viper.Viper) (encryptomatic.Installer, error) {
	i := &Installer{}
	err := v.Unmarshal(i)
	if err != nil {
		return nil, err
	}
	return i, nil
}

// Installer writes certificates to files on a remote server in various formats.
type Installer struct {
	// Host is the remote hostname to connect to.
	Host string

	// Port is the remote port to connect to. Defaults to 22 if not set.
	Port int

	// User is the username to use when connecting.
	User string

	// SSHPrivateKey is a path to the SSH private key to use when connecting.
	SSHPrivateKey string `mapstructure:"ssh_private_key"`

	// HostFingerprint is the OpenSSH SHA-256 fingerprint of the remote server.
	// If blank, then this Installer will fail when creating a connection with the fingerprint in the error message.
	HostFingerprint string `mapstructure:"host_fingerprint"`

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
	BeforeCmd string `mapstructure:"before_cmd"`

	// AfterCmd is a command to execute after writing the new certificate.
	// If empty, no command will be run.
	AfterCmd string `mapstructure:"after_cmd"`

	c  *ssh.Client
	fc *sftp.Client
}

// Cleanup closes any dangling SSH or SFTP connections.
func (i *Installer) Cleanup(ctx context.Context) (err error) {
	if i.fc != nil {
		log.Printf("ssh: closing SFTP client")
		err = i.fc.Close()
	}
	if i.c != nil {
		log.Printf("ssh: closing SSH client")
		err = i.c.Close()
	}
	return err
}

func (i *Installer) conn() (*ssh.Client, error) {
	if i.c != nil {
		return i.c, nil
	}

	port := i.Port
	if port == 0 {
		port = 22
	}

	privKeyBytes, err := ioutil.ReadFile(i.SSHPrivateKey)
	if err != nil {
		return nil, err
	}
	privKey, err := ssh.ParsePrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: i.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(privKey)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if i.HostFingerprint == "" {
				return fmt.Errorf("no host_fingerprint set: remote fingerprint was %q", fp)
			}
			if fp == i.HostFingerprint {
				return nil
			}
			return fmt.Errorf("FINGERPRINT MISMATCH: remote fingerprint was %q; configured fingerprint is %q", fp, i.HostFingerprint)
		},
	}

	addr := net.JoinHostPort(i.Host, fmt.Sprintf("%d", port))
	log.Printf("ssh: connecting to %s", addr)
	c, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	i.c = c
	return i.c, nil
}

func (i *Installer) filesystem() (*sftp.Client, error) {
	if i.fc != nil {
		return i.fc, nil
	}

	conn, err := i.conn()
	if err != nil {
		return nil, err
	}

	log.Printf("ssh: opening SFTP client")
	fc, err := sftp.NewClient(conn)
	if err != nil {
		return nil, err
	}

	i.fc = fc
	return i.fc, nil
}

func (i *Installer) runCmd(ctx context.Context, cmd string) error {
	if len(cmd) == 0 {
		return nil
	}

	log.Printf("ssh: running command %v", cmd)
	conn, err := i.conn()
	if err != nil {
		return err
	}
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}

	if err := sess.Run(cmd); err != nil {
		sess.Close()
		return err
	}

	if err := sess.Close(); err != nil {
		return err
	}

	log.Printf("ssh: command completed")
	return nil
}

// GenerateCSR reads a CSR off disk, if one has been provided.
func (i *Installer) GenerateCSR(ctx context.Context) (*x509.CertificateRequest, error) {
	if i.CertificateRequest == "" {
		// No CertificateRequest, request generation.
		log.Printf("ssh: no CertificateRequest, requesting generation of CSR")
		return nil, nil
	}

	fc, err := i.filesystem()
	if err != nil {
		return nil, fmt.Errorf("ssh: failed to connect: %v", err)
	}

	log.Printf("ssh: loading CSR from %v", i.CertificateRequest)
	f, err := fc.Open(i.CertificateRequest)
	if err != nil {
		return nil, fmt.Errorf("ssh: failed to open %q: %v", i.CertificateRequest, err)
	}
	defer f.Close()

	fbytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("ssh: failed to read %q: %v", i.CertificateRequest, err)
	}

	csrBlock, _ := pem.Decode(fbytes)
	if csrBlock == nil {
		return nil, fmt.Errorf("ssh: CSR is badly formatted")
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
	log.Printf("ssh: inside GetCertificate")

	fc, err := i.filesystem()
	if err != nil {
		return nil, fmt.Errorf("ssh: failed to connect: %v", err)
	}

	candidatePaths := []string{i.FullChain, i.EndEntity, i.FullPrivateChain}
	for _, p := range candidatePaths {
		if p == "" {
			continue
		}
		log.Printf("ssh: checking for existing certificate at %v", p)
		f, err := fc.Open(p)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("ssh: failed to open %v: %v", p, err)
		}
		defer f.Close()

		pemBytes, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("ssh: couldn't read %v: %v", p, err)
		}

		cert, _, err := encryptoutil.PEMToCertificate(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("ssh: %v contains garbage: %v", p, err)
		}
		log.Printf("ssh: found certificate at %v", p)
		return cert, nil
	}

	return nil, nil
}

// SetCertificate installs the provided certificate into the provided files.
func (i *Installer) SetCertificate(ctx context.Context, caBundle []*x509.Certificate, cert *x509.Certificate, pkey crypto.PrivateKey) (err error) {
	log.Printf("ssh: inside SetCertificate")
	if err = i.runCmd(ctx, i.BeforeCmd); err != nil {
		return fmt.Errorf("ssh: failed to run BeforeCmd %v: %v", i.BeforeCmd, err)
	}

	fc, err := i.filesystem()
	if err != nil {
		return fmt.Errorf("ssh: failed to connect: %v", err)
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
		log.Printf("ssh: opening %s", p.fn)
		f, err := fc.OpenFile(p.fn, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return fmt.Errorf("ssh: failed to create %q: %v", p.fn, err)
		}
		if err := f.Chmod(p.mode); err != nil {
			return fmt.Errorf("ssh: failed to chmod %q to %o: %v", p.fn, p.mode, err)
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
	log.Printf("ssh: writing end entity certificate")
	if err := writeOut(encryptoutil.CertificateToPEM(cert), []io.Writer{h.FullChain, h.EndEntity, h.FullPrivateChain}); err != nil {
		return fmt.Errorf("ssh: failed to write end entity certificate: %v", err)
	}

	// 2. Intermediates
	log.Printf("ssh: writing certificate bundle")
	for _, ca := range caBundle {
		if err := writeOut(encryptoutil.CertificateToPEM(ca), []io.Writer{h.FullChain, h.Chain, h.FullPrivateChain}); err != nil {
			return fmt.Errorf("ssh: failed to write intermediate certificate: %v", err)
		}
	}

	// 3. Private Key
	log.Printf("ssh: writing private key")
	pkeyBytes, err := encryptoutil.PrivateKeyToPEM(pkey)
	if err != nil {
		return fmt.Errorf("ssh: failed to serialize private key: %v", err)
	}
	if err := writeOut(pkeyBytes, []io.Writer{h.FullPrivateChain, h.PrivateKey}); err != nil {
		return fmt.Errorf("ssh: failed to write private key: %v", err)
	}

	if err = i.runCmd(ctx, i.AfterCmd); err != nil {
		return fmt.Errorf("ssh: failed to run AfterCmd %v: %v", i.AfterCmd, err)
	}

	return nil
}
