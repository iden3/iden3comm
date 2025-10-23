lint:
	golangci-lint --config .golangci.yml run
#Unit tests
test:
	go test -tags jwx_es256k -v -race -timeout=60s -count=1 ./...
