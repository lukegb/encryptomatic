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
	"time"

	"github.com/digitalocean/godo"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"lukegb.com/encryptomatic"
)

func init() {
	encryptomatic.RegisterVerifier("digitalocean", New)
}

func New(cfg *viper.Viper) (encryptomatic.Verifier, error) {
	v := &DigitalOcean{}
	err := cfg.Unmarshal(v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

type tokenSource oauth2.Token

func (t *tokenSource) Token() (*oauth2.Token, error) {
	ot := oauth2.Token(*t)
	return &ot, nil
}

type createdRecord struct {
	Domain string
	Record *godo.DomainRecord
}

type DigitalOcean struct {
	// PersonalAccessToken for authenticating requests
	PersonalAccessToken string `mapstructure:"personal_access_token"`

	// godo.Client to use when interacting with DigitalOcean
	Client *godo.Client

	knownZones     []godo.Domain
	createdRecords []createdRecord
	lastResp       *godo.Response
}

func (v *DigitalOcean) client(ctx context.Context) (*godo.Client, error) {
	if v.Client != nil {
		return v.Client, nil
	}

	if v.PersonalAccessToken == "" {
		return nil, fmt.Errorf("digitalocean: either Client or PersonalAccessToken must be set")
	}

	token := tokenSource(oauth2.Token{
		AccessToken: v.PersonalAccessToken,
	})
	oauthClient := oauth2.NewClient(ctx, &token)
	client := godo.NewClient(oauthClient)
	client.UserAgent = "encryptomatic (https://lukegb.com/encryptomatic)"
	return client, nil
}

func (v *DigitalOcean) domains(ctx context.Context) ([]godo.Domain, error) {
	if v.knownZones != nil {
		return v.knownZones, nil
	}

	client, err := v.client(ctx)
	if err != nil {
		return nil, err
	}

	page := 1
	isLastPage := false
	var domains []godo.Domain
	for !isLastPage {
		if err := v.waitForRate(ctx); err != nil {
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

func (v *DigitalOcean) waitForRate(ctx context.Context) error {
	resp := v.lastResp
	if resp == nil {
		return nil
	}
	if resp.Rate.Remaining > 0 {
		return nil
	}

	resetTime := resp.Rate.Reset
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline && resetTime.After(deadline) {
		return fmt.Errorf("digitalocean: rate limit reset time (%v) is after context deadline (%v)", resetTime, deadline)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(resetTime.Sub(time.Now())):
	}
	return nil
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

	client, err := v.client(ctx)
	if err != nil {
		return err
	}

	if err := v.waitForRate(ctx); err != nil {
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
	client, err := v.client(ctx)
	if err != nil {
		return err
	}

	for _, record := range v.createdRecords {
		if err := v.waitForRate(ctx); err != nil {
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
