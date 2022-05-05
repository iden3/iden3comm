module github.com/iden3/iden3comm

go 1.17

replace github.com/iden3/jwz => ../jwz

require (
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/iden3/go-circuits v0.0.39
	github.com/iden3/go-iden3-core v0.0.16
	github.com/iden3/go-schema-processor v0.0.22
	github.com/iden3/jwz v0.0.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.1

)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/ethereum/go-ethereum v1.10.17 // indirect
	github.com/iden3/go-iden3-crypto v0.0.13 // indirect
	github.com/iden3/go-merkletree-sql v1.0.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20220126234351-aa10faf2a1f8 // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
