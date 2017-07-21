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
	"time"

	"golang.org/x/oauth2"

	"github.com/digitalocean/godo"
)

const (
	testAccessToken = "MyPersonalAccessToken"
)

func TestNewFromToken(t *testing.T) {
	v := NewFromToken(testAccessToken)
	if v.PersonalAccessToken != testAccessToken {
		t.Errorf("NewFromToken(%q).PersonalAccessToken = %q; want %q", testAccessToken, v.PersonalAccessToken, testAccessToken)
	}
}

func TestTokenSource(t *testing.T) {
	want := oauth2.Token{AccessToken: testAccessToken}
	ts := tokenSource(want)
	got, err := ts.Token()
	if err != nil {
		t.Errorf("ts.Token(): %v", err)
	}
	if *got != want {
		t.Errorf("ts.Token() = %v; want %v", got, want)
	}
}

func TestClient(t *testing.T) {
	v := NewFromToken(testAccessToken)
	ctx := context.Background()
	_, err := v.Client(ctx)
	if err != nil {
		t.Errorf("v.Client(ctx): %v", err)
	}
}

func TestWaitForRate(t *testing.T) {
	v := &DigitalOcean{APIClient: &godo.Client{}}
	ctx := context.Background()
	for _, test := range []struct {
		name          string
		context       func() (context.Context, func())
		lastResp      *godo.Response
		resetDelay    time.Duration
		delaysAtLeast time.Duration
		wantError     bool
	}{
		{
			name:      "no resp",
			lastResp:  nil,
			wantError: false,
		},
		{
			name: "resp with remaining",
			lastResp: &godo.Response{
				Rate: godo.Rate{Remaining: 1},
			},
			wantError: false,
		},
		{
			name:          "resp with reset",
			lastResp:      &godo.Response{},
			resetDelay:    10 * time.Millisecond,
			delaysAtLeast: 10 * time.Millisecond,
			wantError:     false,
		},
		{
			name:       "cancelled context",
			lastResp:   &godo.Response{},
			resetDelay: 10 * time.Millisecond,
			context: func() (context.Context, func()) {
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				return ctx, func() {}
			},
			wantError: true,
		},
		{
			name:       "context deadline too far away",
			lastResp:   &godo.Response{},
			resetDelay: 10 * time.Millisecond,
			context: func() (context.Context, func()) {
				return context.WithDeadline(ctx, time.Now().Add(5*time.Millisecond))
			},
			wantError: true,
		},
	} {
		if test.resetDelay != 0 {
			test.lastResp.Rate.Reset = godo.Timestamp{time.Now().Add(test.resetDelay)}
		}
		ctx := ctx
		var cancel func()
		if test.context != nil {
			ctx, cancel = test.context()
		}
		start := time.Now()
		err := v.WaitForRate(ctx, test.lastResp)
		delay := time.Now().Sub(start)
		if test.wantError != (err != nil) {
			t.Errorf("%v: waitForRate(ctx): %v; wanted error? %v", test.name, err, test.wantError)
		}
		if test.delaysAtLeast > 0 && delay < test.delaysAtLeast {
			t.Errorf("%v: waitForRate(ctx): expected a pause of at least %v; got %v", test.name, test.delaysAtLeast, delay)
		}
		if cancel != nil {
			cancel()
		}
	}
}
