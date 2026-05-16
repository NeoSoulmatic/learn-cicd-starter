package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers    http.Header
		wantAPIKey string
		wantErr    error
		wantErrMsg string
	}{
		"valid api key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key-123"},
			},
			wantAPIKey: "my-secret-key-123",
			wantErr:    nil,
		},
		"no authorization header": {
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		"empty authorization header": {
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		"malformed - missing ApiKey prefix": {
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			wantAPIKey: "",
			wantErrMsg: "malformed authorization header",
		},
		"malformed - only ApiKey without key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey: "",
			wantErrMsg: "malformed authorization header",
		},
		"malformed - missing space": {
			headers: http.Header{
				"Authorization": []string{"ApiKeymy-key"},
			},
			wantAPIKey: "",
			wantErrMsg: "malformed authorization header",
		},
		"malformed - wrong case prefix": {
			headers: http.Header{
				"Authorization": []string{"apikey my-key"},
			},
			wantAPIKey: "",
			wantErrMsg: "malformed authorization header",
		},
		"valid with extra segments": {
			headers: http.Header{
				"Authorization": []string{"ApiKey my-key with spaces"},
			},
			wantAPIKey: "my-key",
			wantErr:    nil,
		},
		"empty key after ApiKey": {
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			wantAPIKey: "",
			wantErr:    nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotAPIKey, gotErr := GetAPIKey(tc.headers)

			// Check API key
			if gotAPIKey != tc.wantAPIKey {
				t.Errorf("GetAPIKey() apiKey = %q, want %q", gotAPIKey, tc.wantAPIKey)
			}

			// Check error
			if tc.wantErr != nil {
				if gotErr != tc.wantErr {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
				}
			} else if tc.wantErrMsg != "" {
				if gotErr == nil {
					t.Errorf("GetAPIKey() error = nil, want error with message %q", tc.wantErrMsg)
				} else if gotErr.Error() != tc.wantErrMsg {
					t.Errorf("GetAPIKey() error = %q, want %q", gotErr.Error(), tc.wantErrMsg)
				}
			} else {
				if gotErr != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", gotErr)
				}
			}
		})
	}
}
