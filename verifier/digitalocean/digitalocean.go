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

// Package digitalocean handles responding to DNS-01 ACME challenges using DigitalOcean domains.
package digitalocean

import (
	"context"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"
	"github.com/spf13/viper"
	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/base/digitalocean"
)

func init() {
	encryptomatic.RegisterVerifier("digitalocean", func(v *viper.Viper) (encryptomatic.Verifier, error) { return New(v) })
}

func New(cfg *viper.Viper) (*DigitalOcean, error) {
	v := &DigitalOcean{}
	err := cfg.Unmarshal(v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

type createdRecord struct {
	Domain string
	Record *godo.DomainRecord
}

type DigitalOcean struct {
	Client digitalocean.DigitalOcean `mapstructure:",squash"`

	knownZones     []godo.Domain
	createdRecords []createdRecord
	lastResp       *godo.Response
}

func (v *DigitalOcean) domains(ctx context.Context) ([]godo.Domain, error) {
	if v.knownZones != nil {
		return v.knownZones, nil
	}

	client, err := v.Client.Client(ctx)
	if err != nil {
		return nil, err
	}

	page := 1
	isLastPage := false
	var domains []godo.Domain
	for !isLastPage {
		if err := v.Client.WaitForRate(ctx, v.lastResp); err != nil {
			return nil, err
		}
		pageDomains, resp, err := client.Domains.List(ctx, &godo.ListOptions{
			Page: page,
		})
		v.lastResp = resp
		if err != nil {
			return nil, fmt.Errorf("digitalocean: error retrieving domain list page %d: %v", page, err)
		}

		domains = append(domains, pageDomains...)

		isLastPage = resp.Links.IsLastPage()
		page++
	}

	v.knownZones = domains
	return v.knownZones, nil
}

func (v *DigitalOcean) domainForName(ctx context.Context, name string) (string, error) {
	domains, err := v.domains(ctx)
	if err != nil {
		return "", err
	}

	matchName := fmt.Sprintf(".%s", name)
	for _, domain := range domains {
		domainName := fmt.Sprintf(".%s", domain.Name)
		if strings.HasSuffix(matchName, domainName) {
			return domain.Name, nil
		}
	}
	return "", nil
}

func (v *DigitalOcean) CanVerify(ctx context.Context, name string) (bool, error) {
	domainName, err := v.domainForName(ctx, name)
	if err != nil {
		return false, err
	}
	return domainName != "", nil
}

func (v *DigitalOcean) VerifyDNS01Record(ctx context.Context, name, value string) error {
	// Check we have a name for this
	domainName, err := v.domainForName(ctx, name)
	if err != nil {
		return err
	} else if domainName == "" {
		return fmt.Errorf("digitalocean: cannot verify name %q", name)
	}

	client, err := v.Client.Client(ctx)
	if err != nil {
		return err
	}

	if err := v.Client.WaitForRate(ctx, v.lastResp); err != nil {
		return err
	}
	record, resp, err := client.Domains.CreateRecord(ctx, domainName, &godo.DomainRecordEditRequest{
		Type: "TXT",
		Name: fmt.Sprintf("_acme-challenge.%s.", name),
		Data: value,
		TTL:  120,
	})
	if err != nil {
		return err
	}
	v.lastResp = resp
	v.createdRecords = append(v.createdRecords, createdRecord{domainName, record})

	return nil
}

func (v *DigitalOcean) Cleanup(ctx context.Context) error {
	client, err := v.Client.Client(ctx)
	if err != nil {
		return err
	}

	for _, record := range v.createdRecords {
		if err := v.Client.WaitForRate(ctx, v.lastResp); err != nil {
			// This is likely unrecoverable.
			return err
		}
		resp, e := client.Domains.DeleteRecord(ctx, record.Domain, record.Record.ID)
		if e != nil {
			err = e
		}
		v.lastResp = resp
	}
	v.createdRecords = nil
	return err
}
