package main

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"vault_env/config"
	"vault_env/log"
	"vault_env/secrets"
	"vault_env/shell_wrapper"
	"vault_env/vault"
)

const version = "0.0.9"
const vault_token_file_name = "/.vault/vault_token"

var versionFlag bool
var testPassword bool
var ignoreSecretsAbsense bool
var secretsManifestPath string
var variableNamePrefix string

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.BoolVar(&versionFlag, "version", false, "prints current version")
	flag.BoolVar(&ignoreSecretsAbsense, "ignore", false, "ignore absense of secrets file, proceed silently")
	flag.BoolVar(&testPassword, "testpassword", false, "skip asking password")
	flag.StringVar(&secretsManifestPath, "manifest", "", "Path to the secrets manifest")
	flag.StringVar(&variableNamePrefix, "prefix", "", "Prepend this prefix to each variable name (i.e. poor's man namespace)")

	flag.Parse()
}

func main() {
	if versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	log.Info("Starting ...")
	config.ReadConfig()

	command_to_wrap := strings.Join(flag.Args(), " ")
	log.Infof("Running command: %s", command_to_wrap)

	secretsManifest, err := secrets.LoadSecretsManifest(secretsManifestPath)
	if err == nil {
		vault_client, err := vault.Connect()
		if err != nil {
			log.Fatalf("Failed to connect to Vault. Error: %v", err)
			os.Exit(-1)
		}

		token := os.Getenv("VAULT_TOKEN")
		if token == "" {
			token = config.Conf.Token
		}

		usr, _ := user.Current()
		dir := usr.HomeDir
		vault_token_file := filepath.Join(dir, vault_token_file_name)

		var username, password string
		if token == "" {
			if _, err = os.Stat(vault_token_file); err == nil {
				log.Debug("Found file: " + vault_token_file)
				data, err := ioutil.ReadFile(vault_token_file)
				if err != nil {
					log.Error("Failed to read token from file. " + err.Error())
				} else {
					token = string(data)
					log.Debug("Loaded token: " + token)

					// Trying to re-use previously saved token
					log.Info("Trying token from " + vault_token_file)
					ttl, err := vault.CheckToken(vault_client.Client, token)
					if err != nil {
						token = ""
					}
					if ttl != nil {
						log.Infof("Token expires in %s", ttl.String())
					}
				}
			} else {
				log.Debug("Didn't find " + vault_token_file)
			}
		}

		if token == "" {
			log.Info("Vault token wasn't specified")
			username, password = credentials()

			token, err = vault.Login(vault_client.Client, username, password)
			if err != nil {
				log.Fatalf("Failed to connect to Vault. Error: %v", err)
				os.Exit(-1)
			}

			vault_dir := filepath.Dir(vault_token_file)
			log.Debug("Checking presence of '" + vault_dir + "'")
			err = nil
			if _, err = os.Stat(vault_dir); err != nil {
				log.Debug("Creating directory " + vault_dir)
				err = os.MkdirAll(vault_dir, 0700)
				if err != nil {
					log.Error("Failed to create vault directory " + vault_token_file)
				}
			}
			if err == nil {
				log.Infof("Saving Vault token to " + vault_token_file)
				ioutil.WriteFile(vault_token_file, []byte(token), 0644)
			}
		}
		err = vault_client.ExtractSecrets(secretsManifest)
		if err != nil {
			log.Fatalf("Failed to extract secrets from Vault. Error: %v", err)
			os.Exit(-1)
		}
		shell_wrapper.SecretsToEnvironmentVariables(secretsManifest, variableNamePrefix)
	} else {
		if !ignoreSecretsAbsense {
			log.Fatalf("Failed to read secrets manifest: %v", err)
			os.Exit(-1)
		} else {
			log.Info("Transparently launching wrapped command ...")
		}
	}
	shell_wrapper.LaunchShellCommand(config.Conf.ShellWrapperCommand, command_to_wrap)
}

func credentials() (username string, password string) {
	reader := bufio.NewReader(os.Stdin)

	user, err := user.Current()
	if err == nil {
		if testPassword {
			username = "test_user"
		} else {
			username = user.Username
		}
	} else {
		fmt.Print("Enter Username: ")
		username, _ = reader.ReadString('\n')
	}
	log.Info("Current username: " + username)

	if testPassword {
		password = "password"
	} else {
		fmt.Print("Enter Password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Failed to read password")
			os.Exit(-1)
		}
		fmt.Println()
		password = string(bytePassword)
	}

	return strings.TrimSpace(username), strings.TrimSpace(password)
}
