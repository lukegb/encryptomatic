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

package digitalocean

import (
	"context"
	"testing"

	"github.com/digitalocean/godo"
	docontext "github.com/digitalocean/godo/context"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/viper"

	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/base/digitalocean"
)

const (
	testAccessToken = "MyPersonalAccessToken"
)

func exampleConfig() *viper.Viper {
	v := viper.New()
	v.Set("type", "digitalocean")
	v.Set("personal_access_token", testAccessToken)
	return v
}

type mockDomainsService struct {
	domains []godo.Domain
	rate    godo.Rate

	godo.DomainsService
}

func (s *mockDomainsService) List(ctx docontext.Context, listOpts *godo.ListOptions) ([]godo.Domain, *godo.Response, error) {
	page := listOpts.Page
	resp := &godo.Response{
		Links: &godo.Links{Pages: &godo.Pages{}},
		Rate:  s.rate,
	}
	if page != len(s.domains) {
		resp.Links.Pages.Last = "/some/other/page"
	}
	return []godo.Domain{s.domains[page-1]}, resp, nil
}

func mockClient() digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		APIClient: &godo.Client{
			Domains: &mockDomainsService{
				domains: []godo.Domain{
					godo.Domain{Name: "example.com", TTL: 120, ZoneFile: "some_zone_file"},
					godo.Domain{Name: "example.net", TTL: 120, ZoneFile: "some_zone_file"},
				},
				rate: godo.Rate{
					Remaining: 100,
				},
			},
		},
	}
}

func TestRegistersWithVerifier(t *testing.T) {
	_, err := encryptomatic.DefaultRegistry.Verifier("digitalocean", viper.New())
	if err != nil {
		t.Errorf("encryptomatic.DefaultRegister.Verifier(%q, nil): %v", "digitalocean", err)
	}
}

func TestParsesConfig(t *testing.T) {
	cfg := exampleConfig()
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%v): %v", cfg, err)
	}

	if v.Client.PersonalAccessToken != testAccessToken {
		t.Errorf("v.Client.PersonalAccessToken = %q; want %q", v.Client.PersonalAccessToken, testAccessToken)
	}
}

func TestDomains(t *testing.T) {
	v := &DigitalOcean{Client: mockClient()}
	want := []godo.Domain{
		godo.Domain{Name: "example.com", TTL: 120, ZoneFile: "some_zone_file"},
		godo.Domain{Name: "example.net", TTL: 120, ZoneFile: "some_zone_file"},
	}

	// first time
	got, err := v.domains(context.Background())
	if err != nil {
		t.Errorf("domains(ctx): %v", err)
	}

	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("domains(ctx) returned bad data: (-got +want)\n%s", diff)
	}
	if v.knownZones == nil {
		t.Errorf("domains(ctx) did not populate knownZones")
	}

	// get cached results
	got, err = v.domains(context.Background())
	if err != nil {
		t.Errorf("domains(ctx) [again]: %v", err)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("domains(ctx) [again] returned bad data: (-got +want)\n%s", diff)
	}
}

func TestCanVerify(t *testing.T) {
	ctx := context.Background()
	v := &DigitalOcean{Client: mockClient()}
	for _, test := range []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"example.net", true},
		{"example.org", false},
		{"blah.example.com", true},
		{"blah.example.org", false},
		{"blahexample.com", false},
	} {
		got, err := v.CanVerify(ctx, test.domain)
		if err != nil {
			t.Errorf("CanVerify(ctx, %q): %v", test.domain, err)
			continue
		}

		if got != test.want {
			t.Errorf("CanVerify(ctx, %q) = %v; want %v", test.domain, got, test.want)
		}
	}
}
