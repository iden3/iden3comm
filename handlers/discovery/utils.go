package discovery

import "strings"

type Feature struct {
	Version    string
	Env        string
	Algs       []string
	CircuitIds []string
}

func ParseFeature(id string) Feature {
	parts := strings.Split(id, ";")
	if len(parts) == 0 {
		return Feature{}
	}

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
