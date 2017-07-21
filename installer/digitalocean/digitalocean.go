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

// Package digitalocean handles installing certificates to load balancers.
package digitalocean

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/digitalocean/godo"
	"github.com/spf13/viper"
	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/base/digitalocean"
	"lukegb.com/encryptomatic/encryptoutil"
)

func init() {
	encryptomatic.RegisterInstaller("digitalocean", func(v *viper.Viper) (encryptomatic.Installer, error) { return New(v) })
}

func New(cfg *viper.Viper) (*DigitalOcean, error) {
	v := &DigitalOcean{}
	err := cfg.Unmarshal(v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

type DigitalOcean struct {
	Client digitalocean.DigitalOcean `mapstructure:",squash"`

	// LoadBalancerID is the ID of the load balancer to install certificates on.
	LoadBalancerID string `mapstructure:"load_balancer_id"`

	// At present, this installer will update *all* of your load balancer's HTTPS, non-tls_passthrough forwarding rules to point to the new certificate.

	lastResp *godo.Response
}

func (d *DigitalOcean) GetCertificate(ctx context.Context) (*x509.Certificate, error) {
	c, err := d.Client.Client(ctx)
	if err != nil {
		return nil, err
	}

	if err := d.Client.WaitForRate(ctx, d.lastResp); err != nil {
		return nil, err
	}
	lb, resp, err := c.LoadBalancers.Get(ctx, d.LoadBalancerID)
	if err != nil {
		return nil, err
	}
	d.lastResp = resp

	var certID string
	var lbAddr string
	for _, rule := range lb.ForwardingRules {
		if rule.TlsPassthrough || rule.EntryProtocol != "https" {
			continue
		}
		if certID != "" && rule.CertificateID != certID {
			// Certificate doesn't match on all rules
			// We treat this as "no certificate found", rather than as an error, since we're planning to overwrite all the certificates anyway.
			return nil, nil
		}
		certID = rule.CertificateID
		lbAddr = net.JoinHostPort(lb.IP, fmt.Sprintf("%s", rule.EntryPort))
	}

	if certID == "" || lbAddr == "" {
		// No certificate here yet
		return nil, nil
	}

	// Check that the certificate object exists (just because!)
	if err := d.Client.WaitForRate(ctx, d.lastResp); err != nil {
		return nil, err
	}
	_, resp, err = c.Certificates.Get(ctx, certID)
	if err != nil {
		return nil, err
	}
	d.lastResp = resp

	// Retrieve the actual certificate
	return encryptoutil.RetrieveCertificate(ctx, "tcp", lbAddr)
}

func (d *DigitalOcean) SetCertificate(ctx context.Context, caBundle []*x509.Certificate, endEntity *x509.Certificate, privKey crypto.PrivateKey) error {
	c, err := d.Client.Client(ctx)
	if err != nil {
		return err
	}

	name := fmt.Sprintf("encryptomatic-%s-%s-%s", endEntity.Subject.CommonName, time.Now().Format("2006-01-02"), endEntity.SerialNumber.Text(16))

	privKeyPEM, err := encryptoutil.PrivateKeyToPEM(privKey)
	if err != nil {
		return err
	}

	caBundlePEM := encryptoutil.CertificateChainToPEM(caBundle)
	endEntityPEM := encryptoutil.CertificateToPEM(endEntity)

	if err := d.Client.WaitForRate(ctx, d.lastResp); err != nil {
		return err
	}
	cert, resp, err := c.Certificates.Create(ctx, &godo.CertificateRequest{
		Name:             name,
		PrivateKey:       string(privKeyPEM),
		LeafCertificate:  string(endEntityPEM),
		CertificateChain: string(caBundlePEM),
	})
	if err != nil {
		return err
	}

	if err := d.Client.WaitForRate(ctx, d.lastResp); err != nil {
		return err
	}
	lb, resp, err := c.LoadBalancers.Get(ctx, d.LoadBalancerID)
	if err != nil {
		return err
	}
	d.lastResp = resp

	lbCopy := *lb
	lbCopy.Region = nil
	var lbReq godo.LoadBalancerRequest
	lbBytes, err := json.Marshal(&lbCopy)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(lbBytes, &lbReq); err != nil {
		return err
	}
	lbReq.Region = lb.Region.Slug

	foundAnyHTTPSRules := false
	for n, rule := range lb.ForwardingRules {
		if rule.TlsPassthrough || rule.EntryProtocol != "https" {
			continue
		}
		foundAnyHTTPSRules = true
		lbReq.ForwardingRules[n].CertificateID = cert.ID
	}
	if !foundAnyHTTPSRules {
		// Adding a new HTTPS forwarding rule -> port 80 as a sane default
		lbReq.ForwardingRules = append(lbReq.ForwardingRules, godo.ForwardingRule{
			EntryProtocol:  "https",
			EntryPort:      443,
			TargetProtocol: "http",
			TargetPort:     80,
			CertificateID:  cert.ID,
			TlsPassthrough: false,
		})
	}

	if err := d.Client.WaitForRate(ctx, d.lastResp); err != nil {
		return err
	}
	_, resp, err = c.LoadBalancers.Update(ctx, d.LoadBalancerID, &lbReq)
	if err != nil {
		return err
	}
	d.lastResp = resp

	return nil
}
