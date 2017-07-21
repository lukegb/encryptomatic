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

package encryptomatic

import (
	"testing"

	"github.com/spf13/viper"
)

func TestVerifierRegistration(t *testing.T) {
	DefaultRegistry.clear()
	type mockVerifier struct {
		Verifier
	}
	want := mockVerifier{}
	RegisterVerifier("test", func(v *viper.Viper) (Verifier, error) {
		return want, nil
	})
	got, err := DefaultRegistry.Verifier("test", nil)
	if err != nil {
		t.Errorf("DefaultRegistry.Verifier(\"test\", nil): %v", err)
	}
	if got != want {
		t.Errorf("DefaultRegistry.Verifier(\"test\", nil) = %v (%T); want %v (%T)", got, got, want, want)
	}
}

func TestNoSuchVerifier(t *testing.T) {
	DefaultRegistry.clear()
	got, err := DefaultRegistry.Verifier("test", nil)
	if err == nil {
		t.Errorf("DefaultRegistry.Verifier(\"test\", nil): got nil; want error")
	}
	if got != nil {
		t.Errorf("DefaultRegistry.Installer(\"test\", nil) = %v; want nil", got)
	}
}

func TestDuplicateVerifierRegistration(t *testing.T) {
	DefaultRegistry.clear()
	RegisterVerifier("test", nil)
	var err interface{}
	(func() {
		defer func() { err = recover() }()
		RegisterVerifier("test", nil)
	})()
	if err == nil {
		t.Errorf("RegisterVerifier did not panic")
	}
}

func TestInstallerRegistration(t *testing.T) {
	DefaultRegistry.clear()
	type mockInstaller struct {
		Installer
	}
	want := mockInstaller{}
	RegisterInstaller("test", func(v *viper.Viper) (Installer, error) {
		return want, nil
	})
	got, err := DefaultRegistry.Installer("test", nil)
	if err != nil {
		t.Errorf("DefaultRegistry.Installer(\"test\", nil): %v", err)
	}
	if got != want {
		t.Errorf("DefaultRegistry.Installer(\"test\", nil) = %v (%T); want %v (%T)", got, got, want, want)
	}
}

func TestNoSuchInstaller(t *testing.T) {
	DefaultRegistry.clear()
	got, err := DefaultRegistry.Installer("test", nil)
	if err == nil {
		t.Errorf("DefaultRegistry.Installer(\"test\", nil): got nil; want error")
	}
	if got != nil {
		t.Errorf("DefaultRegistry.Installer(\"test\", nil) = %v; want nil", got)
	}
}

func TestDuplicateInstallerRegistration(t *testing.T) {
	DefaultRegistry.clear()
	RegisterInstaller("test", nil)
	var err interface{}
	(func() {
		defer func() { err = recover() }()
		RegisterInstaller("test", nil)
	})()
	if err == nil {
		t.Errorf("RegisterInstaller did not panic")
	}
}
