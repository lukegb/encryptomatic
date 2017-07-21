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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCertificateRequestGenerateCSR(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	tests := []struct {
		name         string
		csr          CertificateRequest
		randReader   io.Reader
		wantCSR      bool
		wantValidCSR bool
		wantKey      crypto.PrivateKey
		wantAnyKey   bool
		wantErr      bool
	}{
		{
			name: "raw CSR",
			csr: CertificateRequest{
				Request: &x509.CertificateRequest{
					Raw: []byte("this is not a real certificate request"),
				},
			},
			wantCSR: true,
		},
		{
			name:    "no names",
			csr:     CertificateRequest{Key: k},
			wantErr: true,
		},
		{
			name: "provided key",
			csr: CertificateRequest{
				Names: []string{"example.com"},
				Key:   k,
			},
			wantCSR:      true,
			wantValidCSR: true,
			wantKey:      k,
		},
		{
			name:       "random key",
			randReader: rand.Reader,
			csr: CertificateRequest{
				Names: []string{"example.com"},
			},
			wantAnyKey:   true,
			wantCSR:      true,
			wantValidCSR: true,
		},
		{
			name:       "broken randomness - can't generate key",
			randReader: &io.LimitedReader{N: 0},
			csr: CertificateRequest{
				Names: []string{"example.com"},
			},
			wantErr: true,
		},
		{
			name:       "broken randomness - can't sign CSR",
			randReader: &io.LimitedReader{N: 0},
			csr: CertificateRequest{
				Names: []string{"example.com"},
				Key:   k,
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		gotCSR, gotKey, gotErr := test.csr.generateCSR(test.randReader)
		if test.wantCSR && gotCSR == nil {
			t.Errorf("%v: csr.generateCSR(...) expected csr; got nil", test.name)
		} else if !test.wantCSR && gotCSR != nil {
			t.Errorf("%v: csr.generateCSR(...) didn't expect csr; got one", test.name)
		}
		keyOK := (test.wantAnyKey && gotKey != nil) || (!test.wantAnyKey && gotKey == test.wantKey)
		if !keyOK {
			t.Errorf("%v: csr.generateCSR(...) key = %v; want %v", test.name, gotKey, test.wantKey)
		}
		if !test.wantErr && gotErr != nil {
			t.Errorf("%v: csr.generateCSR(...): %v", test.name, gotErr)
		} else if test.wantErr && gotErr == nil {
			t.Errorf("%v: csr.generateCSR(nil): wanted error, got nil", test.name)
		}

		if test.wantValidCSR && gotCSR != nil {
			gotReq, err := x509.ParseCertificateRequest(gotCSR)
			if err != nil {
				t.Errorf("%v: unable to parse returned certificate request: %v", test.name, err)
				continue
			}

			wantCN := test.csr.Names[0]
			if gotReq.Subject.CommonName != wantCN {
				t.Errorf("%v: gotReq.Subject.CommonName = %q; want %q", test.name, gotReq.Subject.CommonName, wantCN)
			}

			if diff := cmp.Diff(gotReq.DNSNames, test.csr.Names); diff != "" {
				t.Errorf("%v: gotReq.DNSNames differs: (-got +want)\n%s", test.name, diff)
			}
		}
	}
}

func TestCertificateRequestNames(t *testing.T) {
	for _, test := range []struct {
		name      string
		csr       CertificateRequest
		wantNames []string
	}{
		{
			name: "from provided CSR",
			csr: CertificateRequest{
				Request: &x509.CertificateRequest{
					DNSNames: []string{"example.net", "example.com", "example.org"},
				},
			},
			wantNames: []string{"example.net", "example.com", "example.org"},
		},
		{
			name: "from .Names",
			csr: CertificateRequest{
				Names: []string{"example.com", "example.net", "example.org"},
			},
			wantNames: []string{"example.com", "example.net", "example.org"},
		},
	} {
		gotNames := test.csr.names()
		if diff := cmp.Diff(test.wantNames, gotNames); diff != "" {
			t.Errorf("%v: names() returned wrong output: (-got +want)\n%s", test.name, diff)
		}
	}
}
