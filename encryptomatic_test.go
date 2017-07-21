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
	"io"
	"testing"
	"time"

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
		if diff := cmp.Diff(gotNames, test.wantNames); diff != "" {
			t.Errorf("%v: names() returned wrong output: (-got +want)\n%s", test.name, diff)
		}
	}
}

func TestCertificateRequestShouldRenew(t *testing.T) {
	ctx := context.Background()
	shouldRenewBoundary := time.Now().Add(365 * 24 * time.Hour)
	shouldNotRenewBoundary := time.Now().Add(-365 * 24 * time.Hour)

	cert1 := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
		Raw:      []byte("example.com-certificate"),
		NotAfter: time.Now(),
	}
	cert1b := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
		Raw:      []byte("other-example.com-certificate"),
		NotAfter: time.Now(),
	}
	cert2 := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.net",
		},
		DNSNames: []string{"example.net", "example.org"},
		Raw:      []byte("example.net/org-certificate"),
		NotAfter: time.Now(),
	}

	for _, test := range []struct {
		name            string
		targets         []Installer
		names           []string
		renewalBoundary time.Time
		want            bool
		wantErr         bool
	}{
		{
			name:            "no targets",
			renewalBoundary: shouldNotRenewBoundary,
			want:            false,
		},
		{
			name: "errored",
			targets: []Installer{&testInstaller{
				ErrorGetCertificate: fmt.Errorf("eek!"),
			}},
			renewalBoundary: shouldNotRenewBoundary,
			wantErr:         true,
		},
		{
			name:            "no certificate",
			targets:         []Installer{&testInstaller{}},
			renewalBoundary: shouldNotRenewBoundary,
			want:            true,
		},
		{
			name:  "certificate mismatch",
			names: []string{"example.com"},
			targets: []Installer{
				&testInstaller{Certificate: cert1},
				&testInstaller{Certificate: cert1b},
			},
			renewalBoundary: shouldNotRenewBoundary,
			want:            true,
		},
		{
			name: "certificate with bad names",
			targets: []Installer{
				&testInstaller{Certificate: cert2},
			},
			names:           []string{"example.com"},
			renewalBoundary: shouldNotRenewBoundary,
			want:            true,
		},
		{
			name: "certificate expiring",
			targets: []Installer{
				&testInstaller{Certificate: cert1},
			},
			names:           []string{"example.com"},
			renewalBoundary: shouldRenewBoundary,
			want:            true,
		},
		{
			name: "certificate up-to-date",
			targets: []Installer{
				&testInstaller{Certificate: cert1},
			},
			names:           []string{"example.com"},
			renewalBoundary: shouldNotRenewBoundary,
			want:            false,
		},
	} {
		cr := CertificateRequest{Targets: test.targets, Names: test.names}
		got, err := cr.shouldRenew(ctx, test.renewalBoundary)
		if test.wantErr != (err != nil) {
			t.Errorf("%s: shouldRenew(ctx, ...): error was %v; wanted error? %v", test.name, err, test.wantErr)
		}
		if got != test.want {
			t.Errorf("%s: shouldRenew(ctx, ...) = %v; want %v", test.name, got, test.want)
		}
	}
}

func TestTypesForVerifier(t *testing.T) {
	for _, test := range []struct {
		name string
		v    Verifier
		want []string
	}{
		{
			name: "useless verifier",
			v: struct {
				Verifier
			}{},
			want: nil,
		},
		{
			name: "DNS-01 verifier",
			v: struct {
				VerifierDNS01
			}{},
			want: []string{"dns-01"},
		},
	} {
		got := typesForVerifier(test.v)
		if diff := cmp.Diff(got, test.want); diff != "" {
			t.Errorf("%v: typesForVerifier(%+v) returned wrong output: (-got +want)\n%s", test.name, test.v, diff)
		}
	}
}

func TestOptionsToCombinations(t *testing.T) {
	type uselessVerifier struct {
		Name string
		Verifier
	}
	v1 := &uselessVerifier{Name: "v1"}
	v2 := &uselessVerifier{Name: "v2"}
	v3 := &uselessVerifier{Name: "v3"}

	inp := [][]Verifier{
		[]Verifier{v2, v3},
		[]Verifier{v1, v2},
		[]Verifier{v3},
	}

	want := [][]Verifier{
		[]Verifier{v2, v1, v3},
		[]Verifier{v3, v1, v3},
		[]Verifier{v2, v2, v3},
		[]Verifier{v3, v2, v3},
	}

	got := optionsToCombinations(inp)
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("optionsToCombinations(...) returned wrong output: (-got +want)\n%s", diff)
	}
}

func TestStringSetsMatch(t *testing.T) {
	for _, test := range []struct {
		name string
		a, b []string
		want bool
	}{
		{
			name: "nil == nil",
			want: true,
		},
		{
			name: "[a] != nil",
			a:    []string{"a"},
			want: false,
		},
		{
			name: "[a] == [a]",
			a:    []string{"a"},
			b:    []string{"a"},
			want: true,
		},
		{
			name: "[a b] != [a]",
			a:    []string{"a", "b"},
			b:    []string{"a"},
			want: false,
		},
		{
			name: "[a] != [a b]",
			a:    []string{"a"},
			b:    []string{"a", "b"},
			want: false,
		},
		{
			name: "[a b] == [b a]",
			a:    []string{"a", "b"},
			b:    []string{"b", "a"},
			want: true,
		},
		{
			name: "[a b a c u s] == [a b c s u]",
			a:    []string{"a", "b", "a", "c", "u", "s"},
			b:    []string{"a", "b", "c", "s", "u"},
			want: true,
		},
		{
			name: "[a b a c u s] != [a b c s]",
			a:    []string{"a", "b", "a", "c", "u", "s"},
			b:    []string{"a", "b", "c", "s"},
			want: false,
		},
		{
			name: "[a b a c u s] == [a b c s u u u]",
			a:    []string{"a", "b", "a", "c", "u", "s"},
			b:    []string{"a", "b", "c", "s", "u", "u", "u"},
			want: true,
		},
	} {
		got := stringSetsMatch(test.a, test.b)
		if got != test.want {
			t.Errorf("%s: stringSetsMatch(%v, %v) = %v; want %v", test.name, test.a, test.b, got, test.want)
		}
	}
}
