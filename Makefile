lint:
	golangci-lint --config .golangci.yml run
#Unit tests
test:
	go test -v -race -short -tags=jwx_es256k -timeout=60s ./...
