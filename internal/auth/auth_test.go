package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAuth(t *testing.T) {
	tests := map[string]struct {
		input   http.Header
		want    string
		wantErr error
	}{
		"noAuthHeader": {
			input: http.Header{
				"noAuth": []string{"ApiKey blahblah2223"},
			},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"noKey": {
			input: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: ErrMalformedAuthHeader,
		},
		"wrongKeyName": {
			input: http.Header{
				"Authorization": []string{"AciKey blachalahchds1233312apikey"},
			},
			want:    "",
			wantErr: ErrMalformedAuthHeader,
		},
		"allCorrect": {
			input: http.Header{
				"Authorization": []string{"ApiKey blahbalhblaha123apikey"},
			},
			want:    "blahbalhblaha123apikey",
			wantErr: nil,
		},
		"emptyHeader": {
			input:   http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"multipleAuthHeaders": {
			input: http.Header{
				"Authorization": []string{"ApiKey validapikey", "ApiKey anotherapikey"},
			},
			want:    "validapikey",
			wantErr: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
			}
			diff := cmp.Diff(tc.want, got)
			if diff != "" {

				t.Fatalf(diff)
			}
		})
	}
}
