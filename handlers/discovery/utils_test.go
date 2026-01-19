package discovery_test

import (
	"reflect"
	"testing"

	"github.com/iden3/iden3comm/v2/handlers/discovery"
)

func TestParseFeature(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want discovery.Feature
	}{
		{
			name: "full feature",
			id:   "iden3comm/v1;env=application/iden3-zkp-json;alg=groth16;circuitIds=authV3,authV3-8-32",
			want: discovery.Feature{
				Version:    "iden3comm/v1",
				Env:        "application/iden3-zkp-json",
				Algs:       []string{"groth16"},
				CircuitIds: []string{"authV3", "authV3-8-32"},
			},
		},
		{
			name: "multiple algs",
			id:   "iden3comm/v1;alg=alg1,alg2",
			want: discovery.Feature{
				Version: "iden3comm/v1",
				Algs:    []string{"alg1", "alg2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := discovery.ParseFeature(tt.id)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseFeature(%q) = %+v, want %+v", tt.id, got, tt.want)
			}
		})
	}
}
