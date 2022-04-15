module github.com/iden3/iden3comm

go 1.17

replace github.com/iden3/go-schema-processor => ../go-schema-processor

require (
	github.com/google/uuid v1.3.0
	github.com/iden3/go-circuits v0.0.32
	github.com/iden3/go-iden3-core v0.0.14
	github.com/iden3/go-iden3-crypto v0.0.13
	github.com/iden3/go-schema-processor v0.0.18
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	gopkg.in/square/go-jose.v2 v2.6.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/google/go-cmp v0.5.4 // indirect
	github.com/iden3/go-merkletree-sql v1.0.0-pre8 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20220126234351-aa10faf2a1f8 // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)
