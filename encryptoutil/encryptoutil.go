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

// Package encryptoutil provides some useful X.509 utilities.
package encryptoutil

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
)

// NamesFromCertificateRequest retrieves the list of domain names a certificate request is for.
func NamesFromCertificateRequest(req *x509.CertificateRequest) []string {
	var names []string

	if req.Subject.CommonName != "" {
		names = append(names, req.Subject.CommonName)
	}

	for _, n := range req.DNSNames {
		if req.Subject.CommonName == n {
			continue
		}
		names = append(names, n)
	}

	return names
}

// RetrieveCertificate retrieves a certificate from the remote host by dialing it.
func RetrieveCertificate(ctx context.Context, network, addr string) (*x509.Certificate, error) {
	var d net.Dialer
	netConn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(netConn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn.ConnectionState().PeerCertificates[0], nil
}

// RetrieveCertificateFromURL retrieves a certificate from a remote host given a URL.
func RetrieveCertificateFromURL(ctx context.Context, urlStr string) (*x509.Certificate, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	return RetrieveCertificate(ctx, "tcp", u.Host)
}

// CertificateToPEM converts a x509.Certificate into a PEM-encoded slice of bytes.
func CertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// PEMToCertificate parses a PEM-encoded slice of bytes into an x509.Certificate.
func PEMToCertificate(pemBytes []byte) (*x509.Certificate, []byte, error) {
	pemBlock, rest := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, rest, fmt.Errorf("encryptoutil: no PEM data found")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, rest, fmt.Errorf("encryptoutil: certificate failed to parse: %v", err)
	}

	return cert, rest, nil
}

// CertificateChainToPEM converts a certificate and its chain into a PEM-encoded slice of bytes.
func CertificateChainToPEM(caBundle []*x509.Certificate, cert *x509.Certificate) []byte {
	// Convert cert into a PEM-encoded certificate.
	pemCert := CertificateToPEM(cert)

	// Convert caBundle into PEM-encoded certificates.
	certBundle := make([][]byte, len(caBundle)+1)
	certBundle[0] = pemCert
	for n, caCert := range caBundle {
		pemCACert := CertificateToPEM(caCert)
		certBundle[n+1] = pemCACert
	}

	return bytes.Join(certBundle, []byte{'\n'})
}

// CertificateRequestToPEM converts an x509.CertificateRequest into a PEM-encoded slice of bytes.
func CertificateRequestToPEM(req *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: req.Raw,
	})
}

type pkcs8Key struct {
	Version int

	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

// PrivateKeyToPEM converts a provided crypto.PrivateKey into a PEM-encoded slice of bytes.
func PrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	var err error

	k := pkcs8Key{
		PrivateKeyAlgorithm: []asn1.ObjectIdentifier{nil},
	}
	// Convert to ASN.1.
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		k.PrivateKey, err = x509.MarshalECPrivateKey(key)
		k.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{
			1, 2, 840, 10045, 2, 1,
		}
	case *rsa.PrivateKey:
		k.PrivateKey = x509.MarshalPKCS1PrivateKey(key)
		k.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{
			1, 2, 840, 113549, 1, 1, 1,
		}
	default:
		return nil, fmt.Errorf("unknown private key format %T", key)
	}
	if err != nil {
		return nil, err
	}

	asn1Bytes, err := asn1.Marshal(k)
	if err != nil {
		return nil, err
	}

	// Encode as PEM.
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: asn1Bytes,
	}), nil
}

// PEMToPrivateKey parses a slice of bytes containing a PEM-encoded private key into a crypto.Signer.
func PEMToPrivateKey(pemBytes []byte) (crypto.Signer, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("encryptoutil: no valid PEM block")
	}

	var key crypto.Signer
	var err error
	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool
		key, ok = k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("invalid private key returned from ParsePKCS8PrivateKey")
		}
	}

	return key, nil
}
