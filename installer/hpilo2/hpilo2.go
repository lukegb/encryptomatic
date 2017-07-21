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

// Package hpilo2 allows installation of SSL certificates on HP ILO2 machines.
package hpilo2 // import "lukegb.com/encryptomatic/installer/hpilo2"

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"regexp"

	"github.com/spf13/viper"

	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/encryptoutil"
)

const giveMeActualXMLHeader = "<?xml version=\"1.0\"?>\r\n<LOCFG VERSION=\"2.21\" />\r\n"

func init() {
	encryptomatic.RegisterInstaller("hpilo2", New)
}

func New(v *viper.Viper) (encryptomatic.Installer, error) {
	i := &Installer{}
	err := v.Unmarshal(i)
	if err != nil {
		return nil, err
	}
	return i, nil
}

type Installer struct {
	// Username is the ILO2 username to authenticate with.
	Username string

	// Password is the password corresponding to Username.
	Password string

	// Addr is the address of the ILO2 server (e.g. hostname:port)
	Addr string

	// InsecureSkipTLSVerify determines whether TLS certificate verification should be skipped when connecting to ILO2.
	// You probably want this on, at least the first time, when migrating from the ILO2-self-signed certificate.
	InsecureSkipTLSVerify bool `mapstructure:"insecure_skip_tls_verify"`

	// TLSConfig is the TLS configuration to use when connecting to the ILO2 server.
	TLSConfig *tls.Config

	// Dialer is the dialer to use when creating new connections.
	Dialer *net.Dialer
}

func defaultTLSConfig() *tls.Config {
	return &tls.Config{
		// XXX: MaxVersion must be set to TLS 1.0 to avoid a record MAC error.
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS10,

		// XXX: if CipherSuites aren't specified, then the ILO will spuriously return parse errors. Why? No idea.
		CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
	}
}

func (i *Installer) do(ctx context.Context, req interface{}) ([]byte, error) {
	d := i.Dialer
	if d == nil {
		d = &net.Dialer{}
	}

	t := i.TLSConfig
	if t == nil {
		t = defaultTLSConfig()
	}
	i.TLSConfig.InsecureSkipVerify = i.InsecureSkipTLSVerify

	rawConn, err := d.DialContext(ctx, "tcp", i.Addr)
	if err != nil {
		return nil, fmt.Errorf("hpilo2: failed to dial: %v", err)
	}
	defer rawConn.Close()
	conn := tls.Client(rawConn, i.TLSConfig)

	if _, err := fmt.Fprintf(conn, "%s", giveMeActualXMLHeader); err != nil {
		return nil, fmt.Errorf("hpilo2: failed to send XML header: %v", err)
	}

	xmlBytes, err := xml.MarshalIndent(req, " ", "")
	if err != nil {
		return nil, fmt.Errorf("hpilo2: failed to marshal request: %v", err)
	}

	// XXX(lukegb): ILO2 requires that these tags are closing, unfortunately.
	forceClosed := []string{"CSR_USE_CERT_2048PKEY", "CSR_USE_CERT_FQDN", "CERTIFICATE_SIGNING_REQUEST", "RESET_RIB"}
	for _, c := range forceClosed {
		r := regexp.MustCompile(fmt.Sprintf("<(%s( [^>]+)?)></%s>", c, c))
		xmlBytes = r.ReplaceAll(xmlBytes, []byte("<$1/>"))
	}
	log.Printf("hpilo2: sending request: %v", string(xmlBytes))

	if _, err := conn.Write(xmlBytes); err != nil {
		return nil, fmt.Errorf("hpilo2: failed to write request: %v", err)
	}

	resp, err := ioutil.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("hpilo2: failed to read response: %v", err)
	}
	log.Printf("hpilo2: got response: %v", string(resp))
	return resp, nil

}

type ribcl struct {
	XMLName xml.Name `xml:"RIBCL"`
	Version string   `xml:"VERSION,attr"`
	Login   ribclLogin
}

type ribclLogin struct {
	XMLName   xml.Name `xml:"LOGIN"`
	UserLogin string   `xml:"USER_LOGIN,attr"`
	Password  string   `xml:"PASSWORD,attr"`
	RIBInfo   ribclRIBInfo
}

type ribclRIBInfo struct {
	XMLName  xml.Name `xml:"RIB_INFO"`
	Mode     string   `xml:"MODE,attr"`
	Children []interface{}
}

type iloBool bool

func (b iloBool) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	v := "Yes"
	if !b {
		v = "No"
	}

	type real struct {
		XMLName xml.Name
		Value   string `xml:"VALUE,attr"`
	}
	return e.Encode(&real{start.Name, v})
}

type csrCertSettings struct {
	XMLName        xml.Name `xml:"CSR_CERT_SETTINGS"`
	UseCert2048Key iloBool  `xml:"CSR_USE_CERT_2048PKEY"`
	UseCertFQDN    iloBool  `xml:"CSR_USE_CERT_FQDN"`
}

type generateCSR struct {
	XMLName xml.Name `xml:"CERTIFICATE_SIGNING_REQUEST"`
}

type importCertificate struct {
	XMLName     xml.Name `xml:"IMPORT_CERTIFICATE"`
	Certificate []byte   `xml:",innerxml"`
}

type resetRIB struct {
	XMLName xml.Name `xml:"RESET_RIB"`
}

// GenerateCSR generates a new certificate signing request.
func (i *Installer) GenerateCSR(ctx context.Context) (*x509.CertificateRequest, error) {
	log.Printf("hpilo2: generating CSR")

	r := ribcl{
		Version: "2.0",
		Login: ribclLogin{
			UserLogin: i.Username,
			Password:  i.Password,
			RIBInfo: ribclRIBInfo{
				Mode: "write",
				Children: []interface{}{
					/*csrCertSettings{
						UseCert2048Key: true,
						UseCertFQDN:    true,
					},*/
					// assume that the CSR is correct(!)
					generateCSR{},
				},
			},
		},
	}

	resp, err := i.do(ctx, r)
	if err != nil {
		return nil, err
	}

	// XXX(lukegb): parse this properly
	start := bytes.Index(resp, []byte("-----BEGIN CERTIFICATE REQUEST-----"))
	if start == -1 {
		return nil, fmt.Errorf("hpilo2: no CSR was provided by ILO - wait and try again later?")
	}
	csrEnd := "-----END CERTIFICATE REQUEST-----"
	end := bytes.Index(resp[start:], []byte(csrEnd))
	if end == -1 {
		return nil, fmt.Errorf("hpilo2: CSR appears to have been truncated")
	}
	end += start + len(csrEnd)

	csr := resp[start:end]
	csrBlock, _ := pem.Decode(csr)
	if csrBlock == nil {
		return nil, fmt.Errorf("hpilo2: CSR is badly formatted")
	}

	return x509.ParseCertificateRequest(csrBlock.Bytes)
}

// GetCertificate retrieves the currently installed certificate from the ILO, by making a TLS connection to it.
func (i *Installer) GetCertificate(ctx context.Context) (*x509.Certificate, error) {
	log.Printf("hpilo2: retrieving certificate from %v", i.Addr)

	return encryptoutil.RetrieveCertificate(ctx, "tcp", i.Addr)
}

// SetCertificate installs the provided certificate on the ILO.
// The certificate must have been generated with the key from GenerateCSR.
func (i *Installer) SetCertificate(ctx context.Context, caBundle []*x509.Certificate, cert *x509.Certificate, pkey crypto.PrivateKey) error {
	log.Printf("hpilo2: installing certificate to %v", i.Addr)
	// Can't serve the CA bundle :(
	// XXX(lukegb): or can we?

	// Generate the PEM-encoded certificate bundle.
	pemBundle := encryptoutil.CertificateToPEM(cert)

	r := ribcl{
		Version: "2.0",
		Login: ribclLogin{
			UserLogin: i.Username,
			Password:  i.Password,
			RIBInfo: ribclRIBInfo{
				Mode: "write",
				Children: []interface{}{
					importCertificate{Certificate: pemBundle},
					resetRIB{},
				},
			},
		},
	}

	_, err := i.do(ctx, r)
	if err != nil {
		return err
	}

	// TODO(lukegb): check if this actually succeeded
	return nil
}
