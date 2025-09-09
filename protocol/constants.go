package protocol

// Version is a type of supported versions of the protocol used in the accept header
type Version string

const (
	// Iden3CommVersion1 is a V1 version of the protocol used in the accept header
	Iden3CommVersion1 Version = "iden3comm/v1"
)

// JwzAlgorithms is a type of accepted proving algorithms
type JwzAlgorithms string

const (
	// JwzAlgorithmsGroth16 is a groth16 accepted proving algorithm
	JwzAlgorithmsGroth16 JwzAlgorithms = "groth16"
)

// JwsAlgorithms is a type of accepted JWS algorithms
type JwsAlgorithms string

const (
	// JwsAlgorithmsES256K is a ES256K accepted JWS algorithm
	JwsAlgorithmsES256K JwsAlgorithms = "ES256K"

	// JwsAlgorithmsES256KR is a ES256K-R accepted JWS algorithm
	JwsAlgorithmsES256KR JwsAlgorithms = "ES256K-R"
)

// AnoncryptAlgorithms is a type of accepted anoncrypt algorithms
type AnoncryptAlgorithms string

const (
	// AnoncryptECDHESA256KW is a ECDH-ES+A256KW accepted Anoncrypt algorithm
	AnoncryptECDHESA256KW AnoncryptAlgorithms = "ECDH-ES+A256KW"
)
