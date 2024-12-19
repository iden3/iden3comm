package protocol

// AcceptProtocolVersion is a type of supported versions of the protocol used in the accept header
type AcceptProtocolVersion string

const (
	// ProtocolVersionV1 is a V1 version of the protocol used in the accept header
	ProtocolVersionV1 AcceptProtocolVersion = "iden3comm/v1"
)

// AcceptAuthCircuits is a type of accepted authentication circuits
type AcceptAuthCircuits string

const (
	// AcceptAuthCircuitsAuthV2 is authV2 accepted circuit
	AcceptAuthCircuitsAuthV2 AcceptAuthCircuits = "authV2"
	// AcceptAuthCircuitsAuthV3 is authV3 accepted circuit
	AcceptAuthCircuitsAuthV3 AcceptAuthCircuits = "authV3"
)

// AcceptJwzAlgorithms is a type of accepted proving algorithms
type AcceptJwzAlgorithms string

const (
	// AcceptJwzAlgorithmsGroth16 is a groth16 accepted proving algorithm
	AcceptJwzAlgorithmsGroth16 AcceptJwzAlgorithms = "groth16"
)

// AcceptJwsAlgorithms is a type of accepted JWS algorithms
type AcceptJwsAlgorithms string

const (
	// AcceptJwsAlgorithmsES256K is a ES256K accepted JWS algorithm
	AcceptJwsAlgorithmsES256K AcceptJwsAlgorithms = "ES256K"

	// AcceptJwsAlgorithmsES256KR is a ES256K-R accepted JWS algorithm
	AcceptJwsAlgorithmsES256KR AcceptJwsAlgorithms = "ES256K-R"
)
