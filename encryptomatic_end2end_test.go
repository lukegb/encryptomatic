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

package encryptomatic

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/google/go-cmp/cmp"
)

type testInstaller struct {
	Certificate *x509.Certificate
	CABundle    []*x509.Certificate
	PrivateKey  crypto.PrivateKey

	ErrorGetCertificate error
	ErrorSetCertificate error
}

func (t *testInstaller) GetCertificate(ctx context.Context) (*x509.Certificate, error) {
	return t.Certificate, t.ErrorGetCertificate
}

func (t *testInstaller) SetCertificate(ctx context.Context, caBundle []*x509.Certificate, endEntity *x509.Certificate, privKey crypto.PrivateKey) error {
	t.CABundle = caBundle
	t.Certificate = endEntity
	t.PrivateKey = privKey
	return t.ErrorSetCertificate
}

type testDNS01Verifier struct {
	SupportsNames []string
	Records       map[string]string
}

func (v *testDNS01Verifier) CanVerify(ctx context.Context, name string) (bool, error) {
	for _, n := range v.SupportsNames {
		if n == name {
			return true, nil
		}
	}
	return false, nil
}

func (v *testDNS01Verifier) VerifyDNS01Record(ctx context.Context, name, value string) error {
	if v.Records == nil {
		v.Records = make(map[string]string)
	}
	v.Records[fmt.Sprintf("_acme-challenge.%s", name)] = value
	return nil
}

func (v *testDNS01Verifier) getRecord(name string) ([]string, error) {
	if v.Records == nil {
		return nil, nil
	}
	return []string{v.Records[name]}, nil
}

type testACMEClient struct {
	RejectChallenge bool

	Preauthorized bool
}

func (c *testACMEClient) DNS01ChallengeRecord(token string) (string, error) {
	return fmt.Sprintf("RECORD{%s}", token), nil
}

func (c *testACMEClient) Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	ch := *chal
	if !c.RejectChallenge {
		ch.Status = acme.StatusValid
	} else {
		ch.Status = acme.StatusInvalid
	}
	return &ch, nil
}

func (c *testACMEClient) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	if url != "http://example.com/challenge" {
		return nil, fmt.Errorf("no such challenge")
	}
	ch := &acme.Challenge{URI: url}
	if !c.RejectChallenge {
		ch.Status = acme.StatusValid
	} else {
		ch.Status = acme.StatusInvalid
	}
	return ch, nil
}

func (c *testACMEClient) Authorize(ctx context.Context, domain string) (*acme.Authorization, error) {
	auth := &acme.Authorization{
		URI:    "http://example.com/authorization",
		Status: acme.StatusPending,
		Identifier: acme.AuthzID{
			Type:  "dns",
			Value: "example.com",
		},
		Challenges: []*acme.Challenge{
			&acme.Challenge{
				URI:    "http://example.com/challenge",
				Type:   "dns-01",
				Token:  "challenge-token",
				Status: acme.StatusPending,
			},
		},
	}
	if c.Preauthorized {
		auth.Status = acme.StatusValid
	}
	return auth, nil
}

func (c *testACMEClient) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	if url != "http://example.com/authorization" {
		return nil, fmt.Errorf("no such authorization")
	}
	auth := &acme.Authorization{URI: "http://example.com/authorization"}
	if !c.RejectChallenge {
		auth.Status = acme.StatusValid
	} else {
		auth.Status = acme.StatusInvalid
	}
	return auth, nil
}

func (c *testACMEClient) CreateCert(ctx context.Context, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error) {
	req, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, "", fmt.Errorf("ParseCertificateRequest: %v", err)
	}

	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, "", fmt.Errorf("rsa.GenerateKey: %v", err)
	}

	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Fake Root",
		},
	}
	intermediateCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Fake Intermeidate",
		},
	}
	endEntity := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      req.Subject,
		DNSNames:     req.DNSNames,
	}

	intermediateBytes, err := x509.CreateCertificate(rand.Reader, intermediateCert, rootCert, k.Public(), k)
	if err != nil {
		return nil, "", fmt.Errorf("CreateCertificate: %v", err)
	}

	endEntityBytes, err := x509.CreateCertificate(rand.Reader, endEntity, intermediateCert, k.Public(), k)
	if err != nil {
		return nil, "", fmt.Errorf("CreateCertificate: %v", err)
	}

	return [][]byte{
		endEntityBytes,
		intermediateBytes,
	}, "http://example.com/certificate", nil
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	installer := &testInstaller{}
	verifier := &testDNS01Verifier{
		SupportsNames: []string{"example.com"},
	}
	client := &testACMEClient{}
	req := CertificateRequest{
		Targets: []Installer{installer},
		Names:   []string{"example.com"},
	}
	e := &Encryptomatic{
		Verifiers: []Verifier{verifier},
		Client:    client,
	}

	oldGetTXTRecords := getTXTRecords
	getTXTRecords = verifier.getRecord
	defer func() {
		getTXTRecords = oldGetTXTRecords
	}()

	err := e.Request(ctx, []CertificateRequest{req})
	if err != nil {
		t.Errorf("Request: %v", err)
	}

	if installer.Certificate == nil {
		t.Errorf("installer.Certificate = %v after installation", installer.Certificate)
	}
	if installer.Certificate.Subject.CommonName != "example.com" {
		t.Errorf("installer.Certificate.Subject.CommonName = %q; want %q", installer.Certificate.Subject.CommonName, "example.com")
	}
	if diff := cmp.Diff(installer.Certificate.DNSNames, []string{"example.com"}); diff != "" {
		t.Errorf("installer.Certificate.DNSNames incorrect: (-got +want)\n%s", diff)
	}
}
