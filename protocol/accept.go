package protocol

import (
	"github.com/iden3/iden3comm/v2"
)

// AcceptProfile is a struct that represents the accept header
type AcceptProfile struct {
	AcceptedVersion           Version
	Env                       iden3comm.MediaType
	AcceptCircuits            []AuthCircuits
	AcceptJwzAlgorithms       []JwzAlgorithms
	AcceptJwsAlgorithms       []JwsAlgorithms
	AcceptAnoncryptAlgorithms []AnoncryptAlgorithms
}

// Version is a type of supported versions of the protocol used in the accept header
type Version string

const (
	// Version1 is a V1 version of the protocol used in the accept header
	Version1 Version = "iden3comm/v1"
)

// AuthCircuits is a type of accepted authentication circuits
type AuthCircuits string

const (
	// AuthCircuitsAuthV2 is authV2 accepted circuit
	AuthCircuitsAuthV2 AuthCircuits = "authV2"
	// AuthCircuitsAuthV3 is authV3 accepted circuit
	AuthCircuitsAuthV3 AuthCircuits = "authV3"
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
