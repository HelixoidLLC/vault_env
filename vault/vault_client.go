/*
 * Copyright 2016 Igor Moochnick
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vault

import (
	"errors"
	"fmt"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-cleanhttp"
	vaultapi "github.com/hashicorp/vault/api"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"vault_env/config"
	"vault_env/log"
)

type vaultClient struct {
	Token  string
	Client *vaultapi.Client
}

func Connect() (*vaultClient, error) {
	vault := vaultClient{}

	address := os.Getenv("VAULT_ADDR")
	if address == "" {
		address = config.Conf.Url
	}
	if address == "" {
		log.Fatal("Can't find address of a Vault server")
		return nil, errors.New("Can't find address of a Vault server")
	}
	log.Infof("Connecting to Vault at %s", address)

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = config.Conf.Token
	}

	ca_file_path := os.Getenv("VAULT_CACERT")
	if ca_file_path == "" {
		ca_file_path = config.Conf.CaFile
	}
	ca_file_path, err := filepath.Abs(ca_file_path)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("Can't locate CA file")
	}

	vault_cert_path := os.Getenv("VAULT_CLIENT_CERT")
	if vault_cert_path == "" {
		vault_cert_path = config.Conf.CertFile
	}
	vault_cert_path, err = filepath.Abs(vault_cert_path)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("Can't locate Vault client Cert file")
	}

	vault_key_path := os.Getenv("VAULT_CLIENT_KEY")
	if vault_key_path == "" {
		vault_key_path = config.Conf.KeyFile
	}
	vault_key_path, err = filepath.Abs(vault_key_path)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("Can't locate Vault client Key file")
	}

	tls_skip_verify := false
	tls_skip_verify_str := os.Getenv("VAULT_SKIP_VERIFY")
	if tls_skip_verify_str != "" {
		tls_skip_verify, err = strconv.ParseBool("true")
		if err != nil {
			log.Fatal(err)
			return nil, errors.New("Can't parse VAULT_SKIP_VERIFY value")
		}
	} else {
		tls_skip_verify = config.Conf.TlsSkipVerify
	}

	_vaultClient, err := createClient(address, ca_file_path, vault_cert_path, vault_key_path, tls_skip_verify)
	if err == nil {
		vault.Client = _vaultClient
	} else {
		log.Fatal("Failed to create the vault client")
		return nil, errors.New("Failed to create the vault client")
	}

	return &vault, nil
}

func createClient(address string, CaFile string, CertFile string, KeyFile string, TlsSkipVerify bool) (*vaultapi.Client, error) {
	config := vaultapi.DefaultConfig()
	config.Address = address

	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		config.HttpClient.Transport = createTlsTransport(CaFile, CertFile, KeyFile, TlsSkipVerify)
	} else {
		log.Debug("Created non-TLS client")
	}

	client, err := vaultapi.NewClient(config)

	return client, err
}

func createTlsTransport(CaFile string, CertFile string, KeyFile string, TlsSkipVerify bool) http.RoundTripper {

	tlsClientConfig, err := consulapi.SetupTLSConfig(&consulapi.TLSConfig{
		InsecureSkipVerify: TlsSkipVerify,
		CAFile:             CaFile,
		CertFile:           CertFile,
		KeyFile:            KeyFile,
	})

	// We don't expect this to fail given that we aren't
	// parsing any of the input, but we panic just in case
	// since this doesn't have an error return.
	if err != nil {
		panic(err)
	}

	transport := cleanhttp.DefaultPooledTransport()
	transport.TLSClientConfig = tlsClientConfig
	transport.TLSClientConfig.InsecureSkipVerify = true
	return transport
}

func Login(vault *vaultapi.Client, username string, password string) (string, error) {
	data := map[string]interface{}{
		"password": password,
	}
	path := fmt.Sprintf("auth/ldap/login/%s", username)
	secret, err := vault.Logical().Write(path, data)
	if err != nil {
		log.Fatalf("Failed to write to vault: %#v", err)
		return "", errors.New("Failed to write to vault")
	}
	log.Debugf("Got secret: %#v", secret)
	vault.SetToken(secret.Auth.ClientToken)
	return secret.Auth.ClientToken, nil
}

func CheckToken(vault *vaultapi.Client, token string) (*time.Duration, error) {
	vault.SetToken(token)
	secret, err := vault.Logical().Read("auth/token/lookup-self")
	if err != nil {
		log.Error("Failed to get information from Vault about specified token: " + token)
		log.Error(err)
		return nil, err
	}
	log.Debugf("Got secret: %#v", secret)
	data := secret.Data
	ttlStr := getStringFromMap(&data, "ttl", "")
	log.Debug("TTL: " + ttlStr)
	if ttlStr != "" {
		ttl, err := time.ParseDuration(ttlStr + "s")
		if err != nil {
			log.Error("Failed to parse ttl")
			return nil, err
		}

		return &ttl, nil
	}

	return nil, nil
}
