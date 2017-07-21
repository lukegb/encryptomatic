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

// Package encryptomatic handles granting SSL certificates via ACME to devices which may not natively support that.
package encryptomatic // import "lukegb.com/encryptomatic"

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/miekg/dns"

	"lukegb.com/encryptomatic/encryptoutil"

	"golang.org/x/crypto/acme"
	"golang.org/x/sync/errgroup"
)

const (
	renewalLeeway = 2 * 30 * 24 * time.Hour // 90 day certificates -> renew 60 days before due
)

var (
	// variablised so that it can be stubbed out for testing
	getTXTRecords = new(dnsClient).lookupTXT

	pollInitialDelay = 100 * time.Millisecond
	pollTimeout      = 2 * time.Minute
	pollInterval     = 10 * time.Second
)

type dnsClient struct {
	c *dns.Client

	resolver  string
	authority map[string]string
}

func (c *dnsClient) lookupTXT(name string) ([]string, error) {
	if c.resolver == "" {
		c.resolver = "8.8.8.8:53"
	}
	if c.c == nil {
		c.c = &dns.Client{}
	}
	if c.authority == nil {
		c.authority = make(map[string]string)
	}

	if _, ok := c.authority[name]; !ok {
		// Find authority
		m := &dns.Msg{}
		m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
		in, _, err := c.c.Exchange(m, c.resolver)
		if err != nil {
			return nil, err
		}

		if len(in.Ns) == 0 {
			return nil, fmt.Errorf("SOA contains no records")
		}
		soa, ok := in.Ns[0].(*dns.SOA)
		if !ok {
			return nil, fmt.Errorf("Server returned %T instead of a SOA record", in.Ns[0])
		}
		c.authority[name] = fmt.Sprintf("%s:53", soa.Ns)
	}

	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	m.RecursionDesired = false

	in, _, err := c.c.Exchange(m, c.authority[name])
	if err != nil {
		return nil, err
	}

	var recs []string
	for _, r := range in.Answer {
		r, ok := r.(*dns.TXT)
		if !ok {
			continue
		}
		recs = append(recs, r.Txt...)
	}
	return recs, nil
}

// CSRGenerator represents an endpoint which can generate its own certificate request/private key pair.
type CSRGenerator interface {
	GenerateCSR(ctx context.Context) (*x509.CertificateRequest, error)
}

// Installer represents a method of installing a certificate onto a device.
type Installer interface {
	SetCertificate(ctx context.Context, caBundle []*x509.Certificate, cert *x509.Certificate, privKey crypto.PrivateKey) error
	GetCertificate(ctx context.Context) (*x509.Certificate, error)
}

// VerifierDNS01 is a Verifier that supports asserting domain control using the ACME dns-01 method (i.e. the creation of a TXT record).
type VerifierDNS01 interface {
	Verifier
	VerifyDNS01Record(ctx context.Context, name, value string) error
}

// Verifier represents a method of asserting control over a domain.
// They should implement one of the more-specific interfaces, such as VerifierDNS01.
type Verifier interface {
	CanVerify(ctx context.Context, name string) (bool, error)
}

// acmeClient is an internal interface wrapping *acme.Client, used for stubbing out ACME calls during testing.
type acmeClient interface {
	// Challenge mungers
	DNS01ChallengeRecord(token string) (string, error)

	// Challenge-related
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	GetChallenge(ctx context.Context, url string) (*acme.Challenge, error)

	// Authorization-related
	Authorize(ctx context.Context, domain string) (*acme.Authorization, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)

	// Certificate-related
	CreateCert(ctx context.Context, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error)
}

// CertificateRequest describes a request for a single certificate.
type CertificateRequest struct {
	// Targets are the target devices which this certificate should be installed on.
	Targets []Installer

	// Names are the domains which this certificate should be requested for.
	Names []string

	// Key is the private key to use to sign the request. If nil, a private key will be generated.
	Key crypto.PrivateKey

	// Request is the pre-generated, pre-signed request. If set, Names and Key will be ignored.
	Request *x509.CertificateRequest
}

func (r CertificateRequest) generateCSR(rand io.Reader) (csr []byte, key crypto.PrivateKey, err error) {
	if r.Request != nil {
		return r.Request.Raw, nil, nil
	}

	k := r.Key
	if k == nil {
		// Generate a new private key.
		k, err = rsa.GenerateKey(rand, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("encryptomatic: failed to generate new RSA private key: %v", err)
		}
	}

	if len(r.Names) == 0 {
		return nil, nil, fmt.Errorf("encryptomatic: cannot request a certificate with 0 names")
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: r.Names[0], // Just take the first name for the subject.
		},
		DNSNames: r.Names,
	}

	csr, err = x509.CreateCertificateRequest(rand, template, k)
	if err != nil {
		return nil, nil, err
	}
	return csr, k, nil
}

func (r CertificateRequest) names() []string {
	if r.Request != nil {
		return r.Request.DNSNames
	}
	return r.Names
}

func (r CertificateRequest) shouldRenew(ctx context.Context, renewalBoundary time.Time) (bool, error) {
	var cert *x509.Certificate
	// Check whether the certificate is consistent across all the installers.
	for _, t := range r.Targets {
		tCert, err := t.GetCertificate(ctx)
		if err != nil {
			return false, fmt.Errorf("encryptomatic: failed checking if need to renew %v from %T: %v", r.Names, t, err)
		}
		if tCert == nil {
			log.Printf("encryptomatic: must renew %v: no certificate exists yet!", r.Names)
			return true, nil
		}
		if cert != nil && !tCert.Equal(cert) {
			return true, nil
		}
		cert = tCert
		certNames := append(append([]string{}, cert.DNSNames...), cert.Subject.CommonName)
		if !stringSetsMatch(r.Names, certNames) {
			log.Printf("encryptomatic: must renew: names on cert (%v) do not match requested (%v)", certNames, r.Names)
			return true, nil
		}
		if renewalBoundary.After(cert.NotAfter) {
			log.Printf("encryptomatic: must renew %v: not after is %v, renewal boundary is %v", r.Names, cert.NotAfter, renewalBoundary)
			return true, nil
		}
	}
	return false, nil
}

// Encryptomatic ties together Verifiers, a Client, and CertificateRequests.
type Encryptomatic struct {
	// Verifiers is a slice of the available verifiers. They should each implement one of the available verification APIs.
	Verifiers []Verifier

	// Client is the acme.Client to use to retrieve certificates.
	// It should already have been registered with the directory, and the Terms-of-Service agreed to.
	Client acmeClient
}

func typesForVerifier(v Verifier) []string {
	var t []string

	if _, ok := v.(VerifierDNS01); ok {
		t = append(t, "dns-01")
	}

	return t
}

func optionsToCombinations(in [][]Verifier) [][]Verifier {
	// Count combinations.
	count := 1
	for n := 0; n < len(in); n++ {
		count *= len(in[n])
	}

	// Generate combinations.
	out := make([][]Verifier, count)
	for combo := 0; combo < count; combo++ {
		n := combo
		v := make([]Verifier, len(in))
		for i, x := range in {
			v[i] = x[n%len(x)]
			n /= len(x)
		}
		out[combo] = v
	}

	return out
}

func pollUntilReady(ctx context.Context, f func(ctx context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()

	time.Sleep(pollInitialDelay)

	ok, err := f(ctx)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			ok, err := f(ctx)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
	}
}

// authorize makes a particular authorization valid, or errors.
func (e *Encryptomatic) authorize(ctx context.Context, auth *acme.Authorization) (*acme.Authorization, error) {
	switch auth.Status {
	case acme.StatusValid:
		return auth, nil
	case acme.StatusPending:
		// no-op, expected
	default:
		return nil, fmt.Errorf("auth.Status is %v, want %v", auth.Status, acme.StatusPending)
	}

	if auth.Identifier.Type != "dns" {
		return nil, fmt.Errorf("encryptomatic: only 'dns' identifiers can be verified")
	}

	// Work out which combinations we can fulfil.
	combos := auth.Combinations
	if combos == nil {
		combos = [][]int{[]int{}}
		for n := 0; n < len(auth.Challenges); n++ {
			combos[0] = append(combos[0], n)
		}
	}

	challengesToVerifier := make(map[string][]Verifier)
	for _, v := range e.Verifiers {
		ok, err := v.CanVerify(ctx, auth.Identifier.Value)
		if err != nil {
			return nil, fmt.Errorf("verifier %T failed to check if can verify %q: %v", v, auth.Identifier.Value, err)
		}
		if !ok {
			continue
		}

		chals := typesForVerifier(v)
		for _, chal := range chals {
			challengesToVerifier[chal] = append(challengesToVerifier[chal], v)
		}
	}

	scorePossibility := func(vs []Verifier) int {
		dvs := 0
		seenVs := make(map[Verifier]int)
		for _, v := range vs {
			if _, ok := seenVs[v]; !ok {
				seenVs[v] = 1
				dvs++
			}
		}
		return dvs
	}

	// Algorithm is as follows:
	// For each combination:
	// - Generate all combinations of verifiers that will solve that combination.
	// - Score the combination based on how many distinct verifiers it contains.
	var chosenChallenges []*acme.Challenge
	var chosenVerifiers []Verifier
	chosenScore := 0
nextCombo:
	for _, combo := range combos {
		challenges := make([]*acme.Challenge, len(combo))
		verifiers := make([][]Verifier, len(combo))
		for n, cid := range combo {
			challenges[n] = auth.Challenges[cid]
			verifiers[n] = challengesToVerifier[challenges[n].Type]
			if len(verifiers[n]) == 0 {
				// No verifiers can solve this challenge, skip to next combination.
				continue nextCombo
			}
		}

		possibilities := optionsToCombinations(verifiers)
		for _, p := range possibilities {
			s := scorePossibility(p)
			if s > chosenScore && chosenScore != 0 {
				continue
			}
			chosenChallenges = challenges
			chosenVerifiers = p
			chosenScore = s
		}
	}

	if chosenScore == 0 {
		return nil, fmt.Errorf("unable to find suitable combination of verifiers")
	}

	g, gctx := errgroup.WithContext(ctx)
	for n, c := range chosenChallenges {
		n := n
		v := chosenVerifiers[n]
		c := c
		ctx := gctx
		log.Printf("encryptomatic: responding to challenge %+v with verifier %T [%d]", c, v, n)
		g.Go(func() error {
			switch c.Type {
			case "dns-01":
				rec, err := e.Client.DNS01ChallengeRecord(c.Token)
				if err != nil {
					return fmt.Errorf("unable to construct dns-01 challenge record: %v", err)
				}

				dnsv, ok := v.(VerifierDNS01)
				if !ok {
					return fmt.Errorf("verifier %T claimed to support dns-01 but doesn't", v)
				}

				if err := dnsv.VerifyDNS01Record(ctx, auth.Identifier.Value, rec); err != nil {
					return fmt.Errorf("unable to use dns-01 to verify %q: %v", auth.Identifier.Value, err)
				}

				// Poll until TXT record appears, or for 2 minutes.
				log.Printf("encryptomatic: waiting for TXT record to appear [%d]", n)
				err = pollUntilReady(ctx, func(ctx context.Context) (bool, error) {
					txts, err := getTXTRecords(fmt.Sprintf("_acme-challenge.%s", auth.Identifier.Value))
					if err != nil {
						return false, err
					}

					for _, txt := range txts {
						if txt == rec {
							log.Printf("encryptomatic: TXT record appeared [%d]", n)
							return true, nil
						}
					}

					return false, nil
				})
				if err != nil {
					return fmt.Errorf("encryptomatic: failed challenge [%d]: %v", n, err)
				}
			default:
				return fmt.Errorf("can't handle challenge type %q", c.Type)
			}

			var err error
			log.Printf("encryptomatic: notifying server we're up to the task [%d]", n)
			c, err = e.Client.Accept(ctx, c)
			if err != nil {
				return err
			}

			log.Printf("encryptomatic: waiting for challenge to change state [%d]", n)
			return pollUntilReady(ctx, func(ctx context.Context) (bool, error) {
				c, err = e.Client.GetChallenge(ctx, c.URI)
				if err != nil {
					log.Printf("encryptomatic: GetChallenge failed: %v [%d]", err, n)
					return false, err
				}

				switch c.Status {
				case acme.StatusInvalid:
					return false, fmt.Errorf("server rejected challenge with status invalid")
				case acme.StatusValid:
					log.Printf("encryptomatic: challenge -> valid [%d]", n)
					return true, nil
				}
				return false, nil
			})
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return e.Client.WaitAuthorization(ctx, auth.URI)
}

func stringSetsMatch(a, b []string) bool {
	// Build a map - add 1 for "in a" and subtract 1 for "in b". The map should then be full of 0.
	m := make(map[string]int)
	for _, k := range a {
		if _, ok := m[k]; ok {
			// we already included this
			continue
		}
		m[k]++
	}
	for _, k := range b {
		if v, ok := m[k]; ok && v <= 0 {
			// we already removed this
			continue
		}
		m[k]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// Request requests certificates for the provided CertificateRequests.
func (e *Encryptomatic) Request(ctx context.Context, reqs []CertificateRequest) error {
	// If NotAfter is before this, we need to renew!
	renewalBoundary := time.Now().Add(renewalLeeway)

	// Collect the domains we need to authorize - check to see which are up for renewal.
	domainsMap := make(map[string]bool)
	var newReqs []CertificateRequest
	for _, req := range reqs {
		if req.Names == nil {
			req.Names = encryptoutil.NamesFromCertificateRequest(req.Request)
		}

		log.Printf("encryptomatic: checking if we need to renew %v", req.Names)

		mustRenew, err := req.shouldRenew(ctx, renewalBoundary)
		if err != nil {
			return err
		}

		if !mustRenew {
			log.Printf("encryptomatic: no need to renew %v!", req.Names)
			continue
		}

		for _, name := range req.Names {
			domainsMap[name] = true
		}
		newReqs = append(newReqs, req)
	}
	reqs = newReqs

	if len(reqs) == 0 {
		log.Printf("encryptomatic: nothing to do")
		return nil
	}

	// Flatten the map back into a slice.
	domains := make([]string, 0, len(domainsMap))
	for domain := range domainsMap {
		domains = append(domains, domain)
	}
	log.Printf("encryptomatic: calculated domain set as %v", domains)

	// Authorize each of the domains.
	auths := make([]*acme.Authorization, len(domains))
	for _, domain := range domains {
		log.Printf("encryptomatic: authorizing %v", domain)
		auth, err := e.Client.Authorize(ctx, domain)
		if err != nil {
			return fmt.Errorf("encryptomatic: failed to authorize %q: %v", domain, err)
		}

		auth, err = e.authorize(ctx, auth)
		if err != nil {
			return fmt.Errorf("encryptomatic: failed to prove ownership of %q: %v", domain, err)
		}
		if auth.Status != acme.StatusValid {
			return fmt.Errorf("encryptomatic: authorization of %q still has status %v after authorizing", domain, auth.Status)
		}
		auths = append(auths, auth)
	}

	// Go through each request and issue it.
	for _, req := range reqs {
		log.Printf("encryptomatic: issuing certificate for %v", req.names())

		csr, key, err := req.generateCSR(rand.Reader)
		if err != nil {
			return fmt.Errorf("unable to generate CSR for %+v: %v", req, err)
		}

		certChain, _, err := e.Client.CreateCert(ctx, csr, 365*24*time.Hour, true)
		if err != nil {
			return fmt.Errorf("unable to createcert for %+v: %v", req, err)
		}

		var caBundle []*x509.Certificate
		var certificate *x509.Certificate
		for n, certBytes := range certChain {
			c, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return fmt.Errorf("can't ParseCertificate: %v", err)
			}

			if n == 0 {
				certificate = c
			} else {
				caBundle = append(caBundle, c)
			}
		}

		for _, i := range req.Targets {
			log.Printf("encryptomatic: installing certificate using %T", i)
			if err := i.SetCertificate(ctx, caBundle, certificate, key); err != nil {
				return fmt.Errorf("can't SetCertificate: %v", err)
			}
		}
	}

	return nil
}
