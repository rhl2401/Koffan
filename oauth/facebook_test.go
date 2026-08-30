package oauth

import "testing"

func TestParseFacebookProfile(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
		want    Identity
	}{
		{
			name: "happy path",
			body: `{"id":"123456","name":"Ada Lovelace","email":"ada@example.com"}`,
			want: Identity{Provider: "facebook", Subject: "123456", Name: "Ada Lovelace", Email: "ada@example.com", EmailVerified: true},
		},
		{
			name: "email permission denied",
			body: `{"id":"123456","name":"Ada Lovelace"}`,
			want: Identity{Provider: "facebook", Subject: "123456", Name: "Ada Lovelace", Email: "", EmailVerified: false},
		},
		{
			name:    "malformed json",
			body:    `not json`,
			wantErr: true,
		},
		{
			name:    "missing id",
			body:    `{"name":"Ada Lovelace"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFacebookProfile([]byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got identity %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if *got != tt.want {
				t.Fatalf("got %+v, want %+v", *got, tt.want)
			}
		})
	}
}
