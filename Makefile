lint:
	golangci-lint --config .golangci.yml run
#Unit tests
test:
	go test -v -race -short -timeout=60s ./...
