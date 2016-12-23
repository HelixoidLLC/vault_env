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

package secrets

import (
	"fmt"
	"github.com/hashicorp/hcl"
	"io/ioutil"
	"os"
	"vault_env/errors"
	"vault_env/log"
)

type secretsManifest struct {
	Secrets []SecretLocator `hcl:"secret"`
}

type SecretLocator struct {
	Name  string      `hcl:",key"`
	Path  string      `hcl:"path,omitempty"`
	Key   string      `hcl:"key,omitempty"`
	Value interface{} `hcl:"value,omitempty"`
}

func LoadSecretsManifest(secretsManifestPath string) (*[]*SecretLocator, error) {
	log.Infof("Loading secrets from '%s'", secretsManifestPath)

	if secretsManifestPath == "" {
		return nil, errors.New(fmt.Sprintf("Secrets manifest file path can't be empty."))
	}

	if _, err := os.Stat(secretsManifestPath); os.IsNotExist(err) {
		return nil, errors.New(fmt.Sprintf("Secrets manifest file '%s' doesn't exist. %#v", secretsManifestPath, err))
	}

	bytes, err := ioutil.ReadFile(secretsManifestPath)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error reading secrets manifest file %s. %#v", secretsManifestPath, err))
	}

	secretsManifest, err := parseDependenciesManifest(string(bytes))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error parsing secrets manifest file %s. %#v", secretsManifestPath, err))
	}

	secrets := make([]*SecretLocator, len(secretsManifest.Secrets))
	for i, secret := range secretsManifest.Secrets {
		ref_secret := secret
		secrets[i] = &ref_secret
	}

	return &secrets, nil
}

func parseDependenciesManifest(hclText string) (*secretsManifest, error) {
	result := &secretsManifest{}

	hclParseTree, err := hcl.Parse(hclText)
	if err != nil {
		return nil, err
	}

	if err := hcl.DecodeObject(&result, hclParseTree); err != nil {
		return nil, err
	}

	return result, nil
}
