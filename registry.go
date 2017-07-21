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
	"fmt"

	"github.com/spf13/viper"
)

var (
	DefaultRegistry *Registry = nil
)

func init() {
	DefaultRegistry = &Registry{}
	DefaultRegistry.clear()
}

type InstallerFactory func(v *viper.Viper) (Installer, error)
type VerifierFactory func(v *viper.Viper) (Verifier, error)

type Registry struct {
	installers map[string]InstallerFactory
	verifiers  map[string]VerifierFactory
}

func (r *Registry) clear() {
	r.installers = make(map[string]InstallerFactory)
	r.verifiers = make(map[string]VerifierFactory)
}

func (r *Registry) Installer(name string, v *viper.Viper) (Installer, error) {
	f, ok := r.installers[name]
	if !ok {
		return nil, fmt.Errorf("encryptomatic: no installer registered for type %q", name)
	}

	return f(v)
}

func (r *Registry) Verifier(name string, v *viper.Viper) (Verifier, error) {
	f, ok := r.verifiers[name]
	if !ok {
		return nil, fmt.Errorf("encryptomatic: no verifier registered for type %q", name)
	}

	return f(v)
}

func RegisterInstaller(name string, installer InstallerFactory) {
	if _, ok := DefaultRegistry.installers[name]; ok {
		panic(fmt.Sprintf("installer %q is already registered", name))
	}
	DefaultRegistry.installers[name] = installer
}

func RegisterVerifier(name string, verifier VerifierFactory) {
	if _, ok := DefaultRegistry.verifiers[name]; ok {
		panic(fmt.Sprintf("verifier %q is already registered", name))
	}
	DefaultRegistry.verifiers[name] = verifier
}
