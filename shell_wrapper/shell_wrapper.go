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

package shell_wrapper

import (
	"fmt"
	"os"
	"os/exec"
	"vault_env/log"
	"vault_env/secrets"
)

func SecretsToEnvironmentVariables(secrets *[]*secrets.SecretLocator, variableNamePrefix string) {
	for _, secret := range *secrets {
		value := fmt.Sprintf("%s", (*secret).Value)
		var_name := fmt.Sprintf("%s%s", variableNamePrefix, (*secret).Name)
		log.Debugf("Setting env var %s=%s", var_name, value)
		os.Setenv(var_name, value)
	}
}

func LaunchShellCommand(shellWrapper string, command string) {
	if shellWrapper == "" {
		shellWrapper = os.Getenv("SHELL")
	}
	log.Debugf("Using shell wrapper '%s'", shellWrapper)
	log.Debugf("Running command '%s'", command)

	cmd := exec.Command(shellWrapper, "-c", command)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Wait()
}
