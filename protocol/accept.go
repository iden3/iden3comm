package protocol

import (
	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/iden3comm/v2"
)

// AcceptProfile is a struct that represents the accept header
type AcceptProfile struct {
	AcceptedVersion           Version
	Env                       iden3comm.MediaType
	AcceptCircuits            []circuits.CircuitID
	AcceptJwzAlgorithms       []JwzAlgorithms
	AcceptJwsAlgorithms       []JwsAlgorithms
	AcceptAnoncryptAlgorithms []AnoncryptAlgorithms
	AcceptAuthcryptAlgorithms []AuthcryptAlgorithms
}
