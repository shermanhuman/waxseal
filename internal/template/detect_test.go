package template

import "testing"

func TestSuggestRotationMode(t *testing.T) {
	tests := []struct {
		keyName string
		want    string
	}{
		// Generated — passwords
		{"password", "generated"},
		{"rootPassword", "generated"},
		{"root_password", "generated"},
		{"db_password", "generated"},
		{"initial_admin_password", "generated"},

		// Generated — secret material
		{"secret_key_base", "generated"},
		{"encryption_key", "generated"},
		{"signing_key", "generated"},
		{"master_key", "generated"},
		{"webhook_secret", "generated"},
		{"cms_webhook_secret", "generated"},
		{"hmac_secret", "generated"},

		// Generated — tokens
		{"auth_token", "generated"},
		{"session_token", "generated"},
		{"otp_secret", "generated"},

		// Computed — connection strings
		{"database_url", "computed"},
		{"redis_url", "computed"},
		{"rosearch_database_url", "computed"},
		{"breakdown_web_database_url", "computed"},

		// External — vendor credentials
		{"client_id", "external"},
		{"client_secret", "external"},
		{"tekmetric_client_id", "external"},
		{"tekmetric_client_secret", "external"},
		{"github_oauth_client_id", "external"},
		{"github_oauth_client_secret", "external"},
		{"api_key", "external"},
		{"ACCESS_KEY_ID", "external"},
		{"SECRET_ACCESS_KEY", "external"},
		{".dockerconfigjson", "external"},

		// Static — identifiers
		{"username", "static"},
		{"rootUser", "unknown"},           // "user" suffix doesn't match "rootUser" camelCase
		{"initial_admin_email", "static"}, // email suffix → static (config, not a secret)

		// Unknown — no clear pattern
		{"vapid_private_key", "unknown"},
		{"vapid_public_key", "unknown"},
		{"some_random_field", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.keyName, func(t *testing.T) {
			got := SuggestRotationMode(tt.keyName)
			if got != tt.want {
				t.Errorf("SuggestRotationMode(%q) = %q, want %q", tt.keyName, got, tt.want)
			}
		})
	}
}

func TestSuggestRotationModeProductionKeys(t *testing.T) {
	// Verify heuristics match actual production configuration from breakdown-infra
	production := map[string]string{
		// default-postgres-app-credentials
		"password": "generated",
		"username": "static",
		// default-minio-creds
		"rootPassword": "generated",
		// default-metabase-credentials
		"metabaseEncryptionKey": "generated", // now caught by well-known catalog
		// default-ghcr-pull-secret
		".dockerconfigjson": "external",
		// default-breakdown-sites-secrets
		"github_oauth_client_id":        "external",
		"github_oauth_client_secret":    "external",
		"rosearch_database_url":         "computed",
		"rosearch_secret_key_base":      "generated",
		"breakdown_web_database_url":    "computed",
		"breakdown_web_secret_key_base": "generated",
		"cms_webhook_secret":            "generated",
		// default-breakdown-admin-secrets
		"secret_key_base":         "generated",
		"tekmetric_client_id":     "external",
		"tekmetric_client_secret": "external",
		"database_url":            "computed",
		// default-b2-backup-creds
		"ACCESS_KEY_ID":     "external",
		"SECRET_ACCESS_KEY": "external",
	}

	for keyName, wantMode := range production {
		t.Run(keyName, func(t *testing.T) {
			got := SuggestRotationMode(keyName)
			if got != wantMode {
				t.Errorf("SuggestRotationMode(%q) = %q, want %q (production mismatch)", keyName, got, wantMode)
			}
		})
	}
}

func TestSuggestRotationModeWellKnownKeys(t *testing.T) {
	// Verify that every key in the well-known catalog is correctly resolved
	// as "generated" by SuggestRotationMode. This exercises the LookupWellKnown path.
	for keyName, project := range wellKnownGenerated {
		t.Run(project+"/"+keyName, func(t *testing.T) {
			got := SuggestRotationMode(keyName)
			if got != "generated" {
				t.Errorf("SuggestRotationMode(%q) = %q, want %q (well-known: %s)",
					keyName, got, "generated", project)
			}
		})
	}
}

func TestLookupWellKnown(t *testing.T) {
	tests := []struct {
		keyName     string
		wantMode    string
		wantProject string
		wantOK      bool
	}{
		// Exact match
		{"metabaseEncryptionKey", "generated", "metabase", true},
		{"metabaseencryptionkey", "generated", "metabase", true}, // case-insensitive
		{"METABASEENCRYPTIONKEY", "generated", "metabase", true}, // all-caps

		// Various projects
		{"mb_encryption_secret_key", "generated", "metabase", true},
		{"DJANGO_SECRET_KEY", "generated", "django", true},
		{"auth_salt", "generated", "wordpress", true},
		{"gitea__security__secret_key", "generated", "gitea", true},
		{"nextauth_secret", "generated", "nextauth", true},

		// Not in catalog
		{"some_unknown_key", "", "", false},
		{"my_custom_field", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.keyName, func(t *testing.T) {
			mode, project, ok := LookupWellKnown(tt.keyName)
			if ok != tt.wantOK {
				t.Fatalf("LookupWellKnown(%q) ok = %v, want %v", tt.keyName, ok, tt.wantOK)
			}
			if mode != tt.wantMode {
				t.Errorf("LookupWellKnown(%q) mode = %q, want %q", tt.keyName, mode, tt.wantMode)
			}
			if project != tt.wantProject {
				t.Errorf("LookupWellKnown(%q) project = %q, want %q", tt.keyName, project, tt.wantProject)
			}
		})
	}
}
