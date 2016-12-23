test:
	go test -v ./...

integration:
	export DOCKER_TLS_VERIFY=1
	export DOCKER_MACHINE_NAME=dev
	export DOCKER_HOST=tcp://192.168.99.100:2376
	export DOCKER_CERT_PATH=~/.docker/machine/machines/dev
	go test -v --tags=integration ./...

build:
	rm -rf bin
	mkdir -p bin/mac
	GOOS=darwin GOARCH=386 go build -o=bin/mac/vault_env
	chmod +x bin/mac/vault_env
	mkdir -p bin/linux
	GOOS=linux GOARCH=386 go build -o=bin/linux/vault_env
	chmod +x bin/linux/vault_env

run:
	go run vault_env.go

bump:
	gobump patch -w
