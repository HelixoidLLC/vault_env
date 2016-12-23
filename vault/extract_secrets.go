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
	"fmt"
	"vault_env/errors"
	"vault_env/log"
	"vault_env/secrets"
)

func (vault *vaultClient) ExtractSecrets(secrets *[]*secrets.SecretLocator) error {

	for _, secret := range *secrets {
		data, err := vault.extractSecret((*secret).Path, (*secret).Key)
		if err != nil {
			return err
		}
		(*secret).Value = data
	}

	return nil
}

func (vault *vaultClient) extractSecret(path string, key string) (interface{}, error) {
	log.Debugf("Extracting path '%s:%s'", path, key)

	secret, err := vault.Client.Logical().Read(path)
	if err != nil {
		log.Errorf("Can't locate secret at path '%s'. %#v", path, err)
		return nil, err
	}
	if secret == nil {
		log.Errorf("No secret found")
		return nil, errors.New(fmt.Sprintf("No secret found at path '%s:%s'", path, key))
	}

	data := secret.Data
	if key == "" {
		log.Errorf("Can't locate secret at path '%s' with key '%s'. %#v", path, key, err)
		return &data, nil
	}

	if value, ok := data[key]; ok {
		log.Debugf("Got value %#v", value)
		return value, nil
	}

	return nil, errors.New(fmt.Sprintf("Can't locate key '%s' at path '%s'", key, path))
}
