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

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/acme"

	"github.com/spf13/viper"
	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/encryptoutil"
)

// Config file format is as follows:
// modules:
//   cf:
//     type: cloudflare
//     apikey: v1
//     email: v2
//   mybind:
//     type: bind
//     something: else
//   myilo:
//     type: hpilo2
//     username: blah
//     password: blah
//     addr: ilo:12345
//   myhaproxy:
//     type: file
//     full_private_chain: /etc/haproxy/ssl/blah.pem
// clients:
//   acme:
//     key: "/some/path/to/a/key/file"
//     agree_tos: true
//     contact_email: "blah@example.com"
//     verifiers: ['cf', 'mybind']
//     certificates:
//       mynicecert:
//         install_to: ['myilo']
//       myothercert:
//         names:
//           - example.com
//           - example.net
//           - example.org
//         install_to: ['myhaproxy']

// RequestBundle represents an Encryptomatic and all of its associated requests.
type RequestBundle struct {
	name          string
	encryptomatic *encryptomatic.Encryptomatic
	requests      []encryptomatic.CertificateRequest
}

// Cleanupper is something that has cleanup that must run.
type Cleanupper interface {
	Cleanup(context.Context) error
}

// ParsedConfig represents a parsed configuration.
type ParsedConfig struct {
	requests  []RequestBundle
	toCleanup map[string]Cleanupper
}

func LoadConfig(ctx context.Context, v *viper.Viper) (*ParsedConfig, error) {
	mods := v.Sub("modules")

	cfg := ParsedConfig{
		toCleanup: make(map[string]Cleanupper),
	}

	installers := make(map[string]encryptomatic.Installer)
	getInstaller := func(name string) (encryptomatic.Installer, error) {
		if installer, ok := installers[name]; ok {
			return installer, nil
		}

		if strings.Contains(name, ".") {
			return nil, fmt.Errorf(". is reserved within installer names")
		}

		if !mods.IsSet(name) {
			return nil, fmt.Errorf("no configured installer by the name of %q", name)
		}
		v := mods.Sub(name)

		modName := v.GetString("type")
		if modName == "" {
			return nil, fmt.Errorf("installer %q has no configured type", name)
		}

		installer, err := encryptomatic.DefaultRegistry.Installer(modName, v)
		if err != nil {
			return nil, err
		}
		installers[name] = installer

		if c, ok := installer.(Cleanupper); ok {
			cfg.toCleanup[name] = c
		}

		return installer, nil
	}

	verifiers := make(map[string]encryptomatic.Verifier)
	getVerifier := func(name string) (encryptomatic.Verifier, error) {
		if verifier, ok := verifiers[name]; ok {
			return verifier, nil
		}

		if strings.Contains(name, ".") {
			return nil, fmt.Errorf(". is reserved within verifier names")
		}

		if !mods.IsSet(name) {
			return nil, fmt.Errorf("no configured verifier by the name of %q", name)
		}
		v := mods.Sub(name)

		modName := v.GetString("type")
		if modName == "" {
			return nil, fmt.Errorf("verifier %q has no configured type", name)
		}

		verifier, err := encryptomatic.DefaultRegistry.Verifier(modName, v)
		if err != nil {
			return nil, err
		}
		verifiers[name] = verifier

		if c, ok := verifier.(Cleanupper); ok {
			cfg.toCleanup[name] = c
		}

		return verifier, nil
	}

	// Create all of the encryptomatic instances:
	for name := range v.GetStringMap("clients") {
		v := v.Sub(fmt.Sprintf("clients.%s", name))

		// First the ACME client:
		v.SetDefault("agree_tos", false)
		v.SetDefault("key", "/etc/encryptomatic/account.key")
		v.SetDefault("directory_url", acme.LetsEncryptURL)

		// Fetch the key, or create it if it doesn't exist.
		var privKey crypto.Signer
		var createdKey bool
		privKeyBytes, err := ioutil.ReadFile(v.GetString("key"))
		if os.IsNotExist(err) {
			privKey, err = rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, fmt.Errorf("%s: generating new account key: %v", name, err)
			}

			pemBytes, err := encryptoutil.PrivateKeyToPEM(privKey)
			if err != nil {
				return nil, fmt.Errorf("%s: converting account key to PEM: %v", name, err)
			}

			if err := ioutil.WriteFile(v.GetString("key"), pemBytes, 0600); err != nil {
				return nil, fmt.Errorf("%s: writing account key: %v", name, err)
			}

			createdKey = true
		} else if err != nil {
			return nil, fmt.Errorf("%s: reading account key: %v", name, err)
		} else {
			privKey, err = encryptoutil.PEMToPrivateKey(privKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("%s: parsing account key: %v", name, err)
			}
		}

		acmeClient := &acme.Client{
			Key:          privKey,
			DirectoryURL: v.GetString("directory_url"),
		}

		// Register with the server iff we created a new key:
		// XXX(lukegb): register unconditionally to retrieve the account information, once that works.
		if createdKey {
			acc := &acme.Account{}
			contactEmail := v.GetString("contact_email")
			if contactEmail != "" {
				acc.Contact = []string{fmt.Sprintf("mailto:%s", contactEmail)}
			}
			acc, err = acmeClient.Register(ctx, acc, func(tosURL string) bool { return v.GetBool("agree_tos") })
			if err != nil {
				return nil, fmt.Errorf("%s: registering/retrieving account details: %v", name, err)
			}
		}

		// Build all the verifiers:
		var verifiers []encryptomatic.Verifier
		for _, verifierName := range v.GetStringSlice("verifiers") {
			verifier, err := getVerifier(verifierName)
			if err != nil {
				return nil, fmt.Errorf("creating verifier %s: %v", verifierName, err)
			}

			verifiers = append(verifiers, verifier)
		}
		if len(verifiers) == 0 {
			return nil, fmt.Errorf("%s: no verifiers configured", name)
		}

		// Build all the certificate requests:
		var crs []encryptomatic.CertificateRequest
		for crName := range v.GetStringMap("certificates") {
			v := v.Sub(fmt.Sprintf("certificates.%s", crName))

			cr := encryptomatic.CertificateRequest{
				Names: v.GetStringSlice("names"),
			}

			// Build all the installers.
			var installers []encryptomatic.Installer
			for _, installerName := range v.GetStringSlice("install_to") {
				installer, err := getInstaller(installerName)
				if err != nil {
					return nil, fmt.Errorf("creating installer %s: %v", installerName, err)
				}

				// Check if this installer can retrieve a CSR, and if so, retrieve it now:
				if installer, ok := installer.(encryptomatic.CSRGenerator); ok {
					// Disabling this functionality is left down to the CSRGenerator - some devices make it impossible to upload a private key
					// which means that it might be undesirable to permit not generating a CSR on-device.
					csr, err := installer.GenerateCSR(ctx)
					if err != nil {
						return nil, fmt.Errorf("%s/%s/%s: generating CSR: %v", name, crName, installerName, err)
					}

					if csr != nil && len(v.GetStringSlice("install_to")) > 0 {
						// The installer generated a CSR, but we've been requested to install to multiple devices.
						// This makes no sense.
						return nil, fmt.Errorf("%s/%s/%s: CSR generated, but requested to install the certificate to multiple endpoints?", name, crName, installerName)
					}

					cr.Request = csr
				}

				installers = append(installers, installer)
			}
			cr.Targets = installers

			crs = append(crs, cr)
		}

		cfg.requests = append(cfg.requests, RequestBundle{
			name: name,
			encryptomatic: &encryptomatic.Encryptomatic{
				Verifiers: verifiers,
				Client:    acmeClient,
			},
			requests: crs,
		})
	}

	return &cfg, nil
}
