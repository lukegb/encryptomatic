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

// Package digitalocean adds some convenience methods to the DigitalOcean API.
package digitalocean

import (
	"context"
	"fmt"
	"time"

	"github.com/digitalocean/godo"
	"golang.org/x/oauth2"
)

func NewFromToken(accessToken string) *DigitalOcean {
	return &DigitalOcean{
		PersonalAccessToken: accessToken,
	}
}

type tokenSource oauth2.Token

func (t *tokenSource) Token() (*oauth2.Token, error) {
	ot := oauth2.Token(*t)
	return &ot, nil
}

type DigitalOcean struct {
	// PersonalAccessToken for authenticating requests
	PersonalAccessToken string `mapstructure:"personal_access_token"`

	// godo.Client to use when interacting with DigitalOcean
	APIClient *godo.Client
}

func (v *DigitalOcean) Client(ctx context.Context) (*godo.Client, error) {
	if v.APIClient != nil {
		return v.APIClient, nil
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
	v.APIClient = client
	return client, nil
}

func (v *DigitalOcean) WaitForRate(ctx context.Context, resp *godo.Response) error {
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
