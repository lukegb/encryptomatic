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

// Package freenas installs certificates on a FreeNAS 11 server.
package freenas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/spf13/viper"

	"lukegb.com/encryptomatic"
	"lukegb.com/encryptomatic/encryptoutil"
)

func init() {
	encryptomatic.RegisterInstaller("freenas", New)
}

func New(v *viper.Viper) (encryptomatic.Installer, error) {
	i := &Installer{}
	err := v.Unmarshal(i)
	if err != nil {
		return nil, err
	}
	return i, nil
}

// Name and Certificate are usually the only things populated - the rest are left nil.
type importRequest struct {
	Name        string `json:"cert_name"`
	Certificate string `json:"cert_certificate"`
	PrivateKey  string `json:"cert_privatekey"`
	Serial      *int   `json:"cert_serial"`
}

type certificate struct {
	ID   int    `json:"id"`
	Name string `json:"cert_name"`
}

type setCertificateRequest struct {
	CertificateID int `json:"stg_guicertificate"`
}

type Installer struct {
	// Username contains the username to authenticate with. This is usually `root`.
	Username string

	// Password contains the password to authenticate with.
	Password string

	// Base contains the root of your FreeNAS installation web UI, not including /api/. For example, http://freenas.local
	Base string

	// Client is the http.Client to use for making requests.
	Client http.Client
}

func (i *Installer) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx) // push down WithContext until the last possible moment, because it's un-contexty.

	// Attach credentials to req
	req.SetBasicAuth(i.Username, i.Password)

	return i.Client.Do(req)
}

func (i *Installer) send(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return nil, fmt.Errorf("freenas: couldn't marshal request: %v", err)
		}
		reqBody = buf
	}

	r, err := http.NewRequest(method, fmt.Sprintf("%s%s", i.Base, path), reqBody)
	if reqBody != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if err != nil {
		return nil, fmt.Errorf("freenas: can't create request: %v", err)
	}

	resp, err := i.do(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("freenas: unable to contact API: %v", err)
	}
	return resp, nil
}

// GetCertificate retrieves the currently installed certificate from FreeNAS.
func (i *Installer) GetCertificate(ctx context.Context) (*x509.Certificate, error) {
	log.Printf("freenas: retrieving certificate from %v", i.Base)

	return encryptoutil.RetrieveCertificateFromURL(ctx, i.Base)
}

// SetCertificate applies the provided certificate, private key, and certificate authority bundle to FreeNAS.
func (i *Installer) SetCertificate(ctx context.Context, caBundle []*x509.Certificate, cert *x509.Certificate, privKey crypto.PrivateKey) error {
	// Generate the PEM-encoded certificate bundle.
	pemBundle := encryptoutil.CertificateChainToPEM(caBundle, cert)

	// Convert privKey into a PEM-encoded private key.
	pemKey, err := encryptoutil.PrivateKeyToPEM(privKey)
	if err != nil {
		return err
	}

	// Import the certificate.
	myName := fmt.Sprintf("letsencrypt-%s-%s", time.Now().Format("2006-01-02"), cert.SerialNumber.Text(16))
	resp, err := i.send(ctx, "POST", "/api/v1.0/system/certificate/import/", &importRequest{
		Name:        myName,
		Certificate: string(pemBundle),
		PrivateKey:  string(pemKey),
	})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("freenas: API returned unexpected status: %v", resp.Status)
	}

	// Fetch the list of certificates.
	resp, err = i.send(ctx, "GET", "/api/v1.0/system/certificate/", nil)
	if err != nil {
		return fmt.Errorf("freenas: unable to contact API: %v", err)
	}
	var certList []certificate
	if err := json.NewDecoder(resp.Body).Decode(&certList); err != nil {
		return fmt.Errorf("freenas: unable to decode certificate list: %v", err)
	}
	resp.Body.Close()

	cid := -1
	for _, cert := range certList {
		if cert.Name == myName {
			cid = cert.ID
			break
		}
	}
	if cid == -1 {
		return fmt.Errorf("freenas: unable to find certificate we just uploaded")
	}

	// Set as web UI certificate.
	resp, err = i.send(ctx, "PUT", "/api/v1.0/system/settings/", &setCertificateRequest{
		CertificateID: cid,
	})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("freenas: API returned unexpected status: %v", resp.Status)
	}

	// TODO(lukegb): need to reload nginx.
	return nil
}
