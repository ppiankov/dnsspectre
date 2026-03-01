package commands

import "testing"

func TestValidatePlatform(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "empty is valid", input: "", wantErr: false},
		{name: "aws", input: "aws", wantErr: false},
		{name: "gcp", input: "gcp", wantErr: false},
		{name: "azure", input: "azure", wantErr: false},
		{name: "cloudflare", input: "cloudflare", wantErr: false},
		{name: "invalid", input: "digitalocean", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePlatform(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePlatform(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "text", input: "text", wantErr: false},
		{name: "json", input: "json", wantErr: false},
		{name: "sarif", input: "sarif", wantErr: false},
		{name: "spectrehub", input: "spectrehub", wantErr: false},
		{name: "invalid", input: "csv", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
