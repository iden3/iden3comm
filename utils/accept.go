package utils

import (
	"errors"
	"strings"

	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
)

// ParseAcceptProfile parses the accept profile string and returns the AcceptProfile struct
func ParseAcceptProfile(profile string) (protocol.AcceptProfile, error) {
	params := strings.Split(profile, ";")
	if len(params) < 2 {
		return protocol.AcceptProfile{}, errors.New("invalid accept profile value")
	}

	protocolVersion := strings.TrimSpace(params[0])
	if !isProtocolVersion(protocolVersion) {
		return protocol.AcceptProfile{}, errors.New("protocol version '" + protocolVersion + "' not supported")
	}

	envParam := strings.Split(params[1], "=")
	if len(envParam) != 2 {
		return protocol.AcceptProfile{}, errors.New("invalid accept profile 'env' parameter")
	}

	env := strings.TrimSpace(envParam[1])
	if !isMediaType(env) {
		return protocol.AcceptProfile{}, errors.New("envelop '" + env + "' not supported")
	}

	circuitsIndex := -1
	for i, param := range params {
		if strings.Contains(param, "circuitId=") {
			circuitsIndex = i
			break
		}
	}

	if env != string(packers.MediaTypeZKPMessage) && circuitsIndex > 0 {
		return protocol.AcceptProfile{}, errors.New("circuits not supported for env '" + env + "'")
	}

	var circuits []protocol.AcceptAuthCircuits
	if circuitsIndex > 0 {
		circuitsStr := strings.Split(strings.Split(params[circuitsIndex], "=")[1], ",")
		for _, c := range circuitsStr {
			c = strings.TrimSpace(c)
			if !isAcceptAuthCircuits(c) {
				return protocol.AcceptProfile{}, errors.New("circuit '" + c + "' not supported")
			}
			circuits = append(circuits, protocol.AcceptAuthCircuits(c))
		}
	}

	algIndex := -1
	for i, param := range params {
		if strings.Contains(param, "alg=") {
			algIndex = i
			break
		}
	}

	var jwzAlgs []protocol.AcceptJwzAlgorithms
	var jwsAlgs []protocol.AcceptJwsAlgorithms
	var anoncryptAlgs []protocol.AcceptAnoncryptAlgorithms
	if algIndex > 0 {
		algStr := strings.Split(strings.Split(params[algIndex], "=")[1], ",")
		switch env {
		case string(packers.MediaTypeZKPMessage):
			for _, a := range algStr {
				a = strings.TrimSpace(a)
				if !isAcceptJwzAlgorithms(a) {
					return protocol.AcceptProfile{}, errors.New("algorithm '" + a + "' not supported for '" + env + "'")
				}
				jwzAlgs = append(jwzAlgs, protocol.AcceptJwzAlgorithms(a))
			}
		case string(packers.MediaTypeSignedMessage):
			for _, a := range algStr {
				a = strings.TrimSpace(a)
				if !isAcceptJwsAlgorithms(a) {
					return protocol.AcceptProfile{}, errors.New("algorithm '" + a + "' not supported for '" + env + "'")
				}
				jwsAlgs = append(jwsAlgs, protocol.AcceptJwsAlgorithms(a))
			}
		case string(packers.MediaTypeEncryptedMessage):
			for _, a := range algStr {
				a = strings.TrimSpace(a)
				if !isAcceptAnoncryptAlgorithms(a) {
					return protocol.AcceptProfile{}, errors.New("algorithm '" + a + "' not supported for '" + env + "'")
				}
				anoncryptAlgs = append(anoncryptAlgs, protocol.AcceptAnoncryptAlgorithms(a))
			}
		default:
			return protocol.AcceptProfile{}, errors.New("algorithm not supported for '" + env + "'")
		}
	}

	return protocol.AcceptProfile{
		ProtocolVersion:           protocol.AcceptProtocolVersion(protocolVersion),
		Env:                       iden3comm.MediaType(env),
		Circuits:                  circuits,
		AcceptJwsAlgorithms:       jwsAlgs,
		AcceptJwzAlgorithms:       jwzAlgs,
		AcceptAnoncryptAlgorithms: anoncryptAlgs,
	}, nil
}

func isProtocolVersion(value string) bool {
	// List all possible protocol versions
	validVersions := []protocol.AcceptProtocolVersion{
		protocol.ProtocolVersionV1,
	}
	for _, v := range validVersions {
		if protocol.AcceptProtocolVersion(value) == v {
			return true
		}
	}
	return false
}

func isAcceptAuthCircuits(value string) bool {
	// List all possible authentication circuits
	validCircuits := []protocol.AcceptAuthCircuits{
		protocol.AcceptAuthCircuitsAuthV2,
		protocol.AcceptAuthCircuitsAuthV3,
	}
	for _, v := range validCircuits {
		if protocol.AcceptAuthCircuits(value) == v {
			return true
		}
	}
	return false
}

func isAcceptJwzAlgorithms(value string) bool {
	// List all possible JWZ algorithms
	validAlgorithms := []protocol.AcceptJwzAlgorithms{
		protocol.AcceptJwzAlgorithmsGroth16,
	}
	for _, v := range validAlgorithms {
		if protocol.AcceptJwzAlgorithms(value) == v {
			return true
		}
	}
	return false
}

func isAcceptJwsAlgorithms(value string) bool {
	// List all possible JWS algorithms
	validAlgorithms := []protocol.AcceptJwsAlgorithms{
		protocol.AcceptJwsAlgorithmsES256K,
		protocol.AcceptJwsAlgorithmsES256KR,
	}
	for _, v := range validAlgorithms {
		if protocol.AcceptJwsAlgorithms(value) == v {
			return true
		}
	}
	return false
}

func isAcceptAnoncryptAlgorithms(value string) bool {
	// List all possible Anoncrypt algorithms
	validAlgorithms := []protocol.AcceptAnoncryptAlgorithms{
		protocol.AcceptAnoncryptECDHESA256KW,
	}
	for _, v := range validAlgorithms {
		if protocol.AcceptAnoncryptAlgorithms(value) == v {
			return true
		}
	}
	return false
}

func isMediaType(value string) bool {
	// List all possible JWS algorithms
	validAlgorithms := []iden3comm.MediaType{
		packers.MediaTypeEncryptedMessage,
		packers.MediaTypePlainMessage,
		packers.MediaTypeZKPMessage,
		packers.MediaTypeSignedMessage,
	}
	for _, v := range validAlgorithms {
		if iden3comm.MediaType(value) == v {
			return true
		}
	}
	return false
}
