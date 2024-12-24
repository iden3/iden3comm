package utils

import (
	"errors"
	"strings"

	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"
)

const (
	mediaTypePlainMessage     = "application/iden3comm-plain-json"
	mediaTypeEncryptedMessage = "application/iden3comm-encrypted-json"
	mediaTypeZKPMessage       = "application/iden3-zkp-json"
	mediaTypeJWSMessage       = "application/iden3comm-signed-json"
)

// BuildAcceptProfile builds the accept profile string array from the AcceptProfile structures
func BuildAcceptProfile(profiles []protocol.AcceptProfile) ([]string, error) {
	result := []string{}

	for i := range profiles {
		accept := string(profiles[i].AcceptedVersion) + ";env=" + string(profiles[i].Env)

		if len(profiles[i].AcceptCircuits) > 0 && profiles[i].Env != mediaTypeZKPMessage {
			return nil, errors.New("circuits not supported for env '" + string(profiles[i].Env) + "'")
		}

		if len(profiles[i].AcceptCircuits) > 0 {
			circuits := []string{}
			for _, circuit := range profiles[i].AcceptCircuits {
				circuits = append(circuits, string(circuit))
			}
			accept += ";circuitId=" + strings.Join(circuits, ",")
		}

		if len(profiles[i].AcceptAnoncryptAlgorithms) > 0 && profiles[i].Env != mediaTypeEncryptedMessage {
			return nil, errors.New("anoncrypt algorithms not supported for env '" + string(profiles[i].Env) + "'")
		}

		if len(profiles[i].AcceptJwsAlgorithms) > 0 && profiles[i].Env != mediaTypeJWSMessage {
			return nil, errors.New("jws algorithms not supported for env '" + string(profiles[i].Env) + "'")
		}

		if len(profiles[i].AcceptJwzAlgorithms) > 0 && profiles[i].Env != mediaTypeZKPMessage {
			return nil, errors.New("jwz algorithms not supported for env '" + string(profiles[i].Env) + "'")
		}

		if len(profiles[i].AcceptJwzAlgorithms) > 0 {
			algorithms := []string{}
			for _, algorithm := range profiles[i].AcceptJwzAlgorithms {
				algorithms = append(algorithms, string(algorithm))
			}
			accept += ";alg=" + strings.Join(algorithms, ",")
		}
		if len(profiles[i].AcceptJwsAlgorithms) > 0 {
			algorithms := []string{}
			for _, algorithm := range profiles[i].AcceptJwsAlgorithms {
				algorithms = append(algorithms, string(algorithm))
			}
			accept += ";alg=" + strings.Join(algorithms, ",")
		}
		if len(profiles[i].AcceptAnoncryptAlgorithms) > 0 {
			algorithms := []string{}
			for _, algorithm := range profiles[i].AcceptAnoncryptAlgorithms {
				algorithms = append(algorithms, string(algorithm))
			}
			accept += ";alg=" + strings.Join(algorithms, ",")
		}

		result = append(result, accept)
	}

	return result, nil
}

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

	if env != string(mediaTypeZKPMessage) && circuitsIndex > 0 {
		return protocol.AcceptProfile{}, errors.New("circuits not supported for env '" + env + "'")
	}

	var circuits []protocol.AuthCircuits
	if circuitsIndex > 0 {
		circuitsStr := strings.Split(strings.Split(params[circuitsIndex], "=")[1], ",")
		for _, c := range circuitsStr {
			c = strings.TrimSpace(c)
			if !isAcceptAuthCircuits(c) {
				return protocol.AcceptProfile{}, errors.New("circuit '" + c + "' not supported")
			}
			circuits = append(circuits, protocol.AuthCircuits(c))
		}
	}

	algIndex := -1
	for i, param := range params {
		if strings.Contains(param, "alg=") {
			algIndex = i
			break
		}
	}

	var jwzAlgs []protocol.JwzAlgorithms
	var jwsAlgs []protocol.JwsAlgorithms
	var anoncryptAlgs []protocol.AnoncryptAlgorithms
	if algIndex > 0 {
		algStr := strings.Split(strings.Split(params[algIndex], "=")[1], ",")
		switch env {
		case mediaTypeZKPMessage:
			for _, a := range algStr {
				a = strings.TrimSpace(a)
				if !isAcceptJwzAlgorithms(a) {
					return protocol.AcceptProfile{}, errors.New("algorithm '" + a + "' not supported for '" + env + "'")
				}
				jwzAlgs = append(jwzAlgs, protocol.JwzAlgorithms(a))
			}
		case mediaTypeJWSMessage:
			for _, a := range algStr {
				a = strings.TrimSpace(a)
				if !isAcceptJwsAlgorithms(a) {
					return protocol.AcceptProfile{}, errors.New("algorithm '" + a + "' not supported for '" + env + "'")
				}
				jwsAlgs = append(jwsAlgs, protocol.JwsAlgorithms(a))
			}
		case mediaTypeEncryptedMessage:
			for _, a := range algStr {
				a = strings.TrimSpace(a)
				if !isAcceptAnoncryptAlgorithms(a) {
					return protocol.AcceptProfile{}, errors.New("algorithm '" + a + "' not supported for '" + env + "'")
				}
				anoncryptAlgs = append(anoncryptAlgs, protocol.AnoncryptAlgorithms(a))
			}
		default:
			return protocol.AcceptProfile{}, errors.New("algorithm not supported for '" + env + "'")
		}
	}

	return protocol.AcceptProfile{
		AcceptedVersion:           protocol.Version(protocolVersion),
		Env:                       iden3comm.MediaType(env),
		AcceptCircuits:            circuits,
		AcceptJwsAlgorithms:       jwsAlgs,
		AcceptJwzAlgorithms:       jwzAlgs,
		AcceptAnoncryptAlgorithms: anoncryptAlgs,
	}, nil
}

func isProtocolVersion(value string) bool {
	// List all possible protocol versions
	validVersions := []protocol.Version{
		protocol.Version1,
	}
	for _, v := range validVersions {
		if protocol.Version(value) == v {
			return true
		}
	}
	return false
}

func isAcceptAuthCircuits(value string) bool {
	// List all possible authentication circuits
	validCircuits := []protocol.AuthCircuits{
		protocol.AuthCircuitsAuthV2,
		protocol.AuthCircuitsAuthV3,
	}
	for _, v := range validCircuits {
		if protocol.AuthCircuits(value) == v {
			return true
		}
	}
	return false
}

func isAcceptJwzAlgorithms(value string) bool {
	// List all possible JWZ algorithms
	validAlgorithms := []protocol.JwzAlgorithms{
		protocol.JwzAlgorithmsGroth16,
	}
	for _, v := range validAlgorithms {
		if protocol.JwzAlgorithms(value) == v {
			return true
		}
	}
	return false
}

func isAcceptJwsAlgorithms(value string) bool {
	// List all possible JWS algorithms
	validAlgorithms := []protocol.JwsAlgorithms{
		protocol.JwsAlgorithmsES256K,
		protocol.JwsAlgorithmsES256KR,
	}
	for _, v := range validAlgorithms {
		if protocol.JwsAlgorithms(value) == v {
			return true
		}
	}
	return false
}

func isAcceptAnoncryptAlgorithms(value string) bool {
	// List all possible Anoncrypt algorithms
	validAlgorithms := []protocol.AnoncryptAlgorithms{
		protocol.AnoncryptECDHESA256KW,
	}
	for _, v := range validAlgorithms {
		if protocol.AnoncryptAlgorithms(value) == v {
			return true
		}
	}
	return false
}

func isMediaType(value string) bool {
	// List all possible JWS algorithms
	validAlgorithms := []iden3comm.MediaType{
		mediaTypeEncryptedMessage,
		mediaTypePlainMessage,
		mediaTypeZKPMessage,
		mediaTypeJWSMessage,
	}
	for _, v := range validAlgorithms {
		if iden3comm.MediaType(value) == v {
			return true
		}
	}
	return false
}
