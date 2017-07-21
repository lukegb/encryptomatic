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
	"fmt"
	"os"

	"github.com/spf13/viper"

	_ "lukegb.com/encryptomatic/installer/digitalocean"
	_ "lukegb.com/encryptomatic/installer/file"
	_ "lukegb.com/encryptomatic/installer/freenas"
	_ "lukegb.com/encryptomatic/installer/hpilo2"
	_ "lukegb.com/encryptomatic/installer/ssh"

	_ "lukegb.com/encryptomatic/verifier/cloudflare"
	_ "lukegb.com/encryptomatic/verifier/digitalocean"
)

func main() {
	ctx := context.Background()

	v := viper.New()
	v.SetConfigName("encryptomatic")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.config/encryptomatic")
	v.AddConfigPath("/etc/encryptomatic")
	if err := v.ReadInConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read configuration file: %v\n", err)
		os.Exit(1)
	}

	cfg, err := LoadConfig(ctx, v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse configuration: %v\n", err)
		os.Exit(1)
	}

	for _, b := range cfg.requests {
		if err := b.encryptomatic.Request(ctx, b.requests); err != nil {
			fmt.Fprintf(os.Stderr, "Failed requesting certificates from %v: %v", b.name, err)
		}
	}

	for cn, c := range cfg.toCleanup {
		if err := c.Cleanup(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to run %v's cleanup - there may be some residue: %v", cn, err)
		}
	}
}
