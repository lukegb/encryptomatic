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

// Package cloudflare automates verification of domain control using Cloudflare's API.
package cloudflare // import "lukegb.com/encryptomatic/verifier/cloudflare"

import (
	"context"
	"fmt"
	"log"
	"strings"

	"lukegb.com/encryptomatic"

	cf "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/viper"
)

func init() {
	encryptomatic.RegisterVerifier("cloudflare", New)
}

func New(v *viper.Viper) (encryptomatic.Verifier, error) {
	i := &Verifier{}
	err := v.Unmarshal(i)
	if err != nil {
		return nil, err
	}
	return i, nil
}

type Verifier struct {
	// APIKey is the API key that should be used against the Cloudflare API.
	APIKey string `mapstructure:"api_key"`

	// Email is the email address to which APIKey belongs.
	Email string

	api            *cf.API
	zones          []cf.Zone
	createdRecords []cf.DNSRecord
}

func (v *Verifier) cf() *cf.API {
	if v.api == nil {
		var err error
		v.api, err = cf.New(v.APIKey, v.Email)
		if err != nil {
			panic(err)
		}
	}
	return v.api
}

type noMatchingZoneError struct {
	zone string
}

func (e noMatchingZoneError) Error() string {
	return fmt.Sprintf("cloudflare: no matching zone for %s", e.zone)
}

// nameToZoneID returns the zone ID containing the specified name.
func (v *Verifier) nameToZoneID(ctx context.Context, name string) (string, error) {
	if v.zones == nil {
		// Get the list of zones.
		var err error
		v.zones, err = v.cf().ListZones()
		if err != nil {
			return "", fmt.Errorf("cloudflare: failed to retrieve list of zones: %v", err)
		}
	}

	// Check each zone to see if it's a maximal suffix of the name we want.
	// We want the longest zone name which is a maximal suffix.
	var match string
	var matchedZone cf.Zone
	testName := fmt.Sprintf(".%s", name)
	for _, z := range v.zones {
		candidate := fmt.Sprintf(".%s", z.Name)
		if len(candidate) < len(match) {
			// This couldn't possibly be a better match than we have already.
			continue
		}

		if strings.HasSuffix(testName, candidate) {
			match = z.Name
			matchedZone = z
		}
	}
	if match == "" {
		return "", noMatchingZoneError{name}
	}

	return matchedZone.ID, nil
}

// CanVerify checks whether this verifier can assert control over the named record.
func (v *Verifier) CanVerify(ctx context.Context, name string) (bool, error) {
	log.Printf("cloudflare: checking if CanVerify %v", name)
	_, err := v.nameToZoneID(ctx, name)
	if err != nil {
		if _, ok := err.(noMatchingZoneError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// VerifyDNS01Record verifies control of a domain using a TXT record.
// If completed successfully, Cleanup should be called later to clean up the created record.
func (v *Verifier) VerifyDNS01Record(ctx context.Context, name, value string) error {
	log.Printf("cloudflare: VerifyDNS01Record(%v, %v)", name, value)

	// Get the Zone ID for this name.
	zoneID, err := v.nameToZoneID(ctx, name)
	if err != nil {
		return err
	}

	// Create the TXT record.
	rec := cf.DNSRecord{
		Type:    "TXT",
		Name:    fmt.Sprintf("_acme-challenge.%s", name),
		Content: value,
		TTL:     120,
	}
	recResp, err := v.cf().CreateDNSRecord(zoneID, rec)
	if err != nil {
		return fmt.Errorf("cloudflare: failed to CreateDNSRecord: %v", err)
	}
	if !recResp.Success {
		return fmt.Errorf("cloudflare: CreateDNSRecord returned errors: %v", recResp.Errors)
	}

	v.createdRecords = append(v.createdRecords, recResp.Result)
	return nil
}

// Cleanup cleans up any DNS records created.
func (v *Verifier) Cleanup(ctx context.Context) error {
	var err error
	for _, cr := range v.createdRecords {
		log.Printf("cloudflare: cleaning up created record: ZoneID=%v, ID=%v", cr.ZoneID, cr.ID)
		e := v.cf().DeleteDNSRecord(cr.ZoneID, cr.ID)
		if e != nil {
			err = e
		}
	}
	v.createdRecords = nil
	return err
}
