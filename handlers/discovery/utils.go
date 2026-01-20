package discovery

import "strings"

// Feature represents a parsed feature with its components
type Feature struct {
	Version    string
	Env        string
	Algs       []string
	CircuitIds []string
}

// ParseFeature parses a feature ID string into a Feature struct
func ParseFeature(id string) Feature {
	id = strings.TrimSpace(id)
	if id == "" {
		return Feature{}
	}
	parts := strings.Split(id, ";")

	f := Feature{
		Version: parts[0],
	}

	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if value == "" {
			continue
		}

		switch key {
		case "env":
			f.Env = value
		case "alg":
			f.Algs = strings.Split(value, ",")
		case "circuitIds":
			f.CircuitIds = strings.Split(value, ",")
		}
	}
	return f
}
