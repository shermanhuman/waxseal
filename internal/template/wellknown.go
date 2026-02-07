package template

import "strings"

// wellKnownGenerated maps lowercase key names from popular self-hosted open-source
// projects to a short project tag. Every key listed here is an internal secret that
// can be safely auto-rotated (generated mode) without coordinating with an external
// service.
//
// The map is checked by SuggestRotationMode before falling back to pattern heuristics,
// so it catches camelCase / non-standard names that patterns would miss
// (e.g. "metabaseEncryptionKey").
//
// To add a new project: append entries with the project name as the value.
// Keep entries sorted by project, then alphabetical within each project.
var wellKnownGenerated = map[string]string{

	// ── Authentik ──────────────────────────────────────────────────────────
	"authentik_secret_key":         "authentik",
	"authentik_bootstrap_password": "authentik",

	// ── Authelia ───────────────────────────────────────────────────────────
	"jwt_secret":             "authelia", // also used by Immich, Supabase, etc.
	"session_secret":         "authelia",
	"storage_encryption_key": "authelia",

	// ── Budibase ───────────────────────────────────────────────────────────
	"bb_admin_user_password": "budibase",
	"internal_api_key":       "budibase",

	// ── Directus ───────────────────────────────────────────────────────────
	"directus_secret": "directus",
	"directus_key":    "directus",

	// ── Django ─────────────────────────────────────────────────────────────
	"django_secret_key": "django",

	// ── Drone CI ───────────────────────────────────────────────────────────
	"drone_rpc_secret":    "drone",
	"drone_cookie_secret": "drone",

	// ── Ghost ──────────────────────────────────────────────────────────────
	"ghost_database__connection__password": "ghost",

	// ── Gitea / Forgejo ────────────────────────────────────────────────────
	"gitea__security__secret_key":     "gitea",
	"gitea__security__internal_token": "gitea",
	"gitea__oauth2__jwt_secret":       "gitea",
	"gitea__server__lfs_jwt_secret":   "gitea",

	// ── GitLab ─────────────────────────────────────────────────────────────
	"gitlab_secrets_secret_key_base": "gitlab",
	"gitlab_secrets_otp_key_base":    "gitlab",
	"gitlab_secrets_db_key_base":     "gitlab",

	// ── Grafana ────────────────────────────────────────────────────────────
	"gf_security_secret_key":     "grafana",
	"gf_security_admin_password": "grafana",

	// ── Immich ─────────────────────────────────────────────────────────────
	"immich_jwt_secret": "immich",
	"db_password":       "immich", // generic but very common in compose stacks

	// ── Keycloak ───────────────────────────────────────────────────────────
	"keycloak_admin_password": "keycloak",
	"kc_db_password":          "keycloak",

	// ── Laravel ────────────────────────────────────────────────────────────
	"app_key": "laravel",

	// ── MariaDB ────────────────────────────────────────────────────────────
	"mariadb_root_password": "mariadb",
	"mariadb_password":      "mariadb",
	"mysql_root_password":   "mysql",
	"mysql_password":        "mysql",

	// ── Matrix Synapse ─────────────────────────────────────────────────────
	"synapse_registration_shared_secret": "synapse",
	"synapse_macaroon_secret_key":        "synapse",
	"synapse_form_secret":                "synapse",

	// ── Mattermost ─────────────────────────────────────────────────────────
	"mm_sqlsettings_atrestencryptkey": "mattermost",

	// ── Metabase ───────────────────────────────────────────────────────────
	"mb_encryption_secret_key": "metabase",
	"mb_db_pass":               "metabase",
	"metabaseencryptionkey":    "metabase", // camelCase variant (k8s secret key)

	// ── MinIO ──────────────────────────────────────────────────────────────
	"minio_root_password": "minio",
	"minio_secret_key":    "minio",

	// ── MongoDB ────────────────────────────────────────────────────────────
	"mongo_initdb_root_password": "mongodb",

	// ── n8n ────────────────────────────────────────────────────────────────
	"n8n_encryption_key": "n8n",

	// ── Nextcloud ──────────────────────────────────────────────────────────
	"nextcloud_admin_password": "nextcloud",

	// ── NextAuth / Auth.js ─────────────────────────────────────────────────
	"nextauth_secret": "nextauth",

	// ── Outline ────────────────────────────────────────────────────────────
	"secret_key":   "outline", // also generic; many apps use this
	"utils_secret": "outline",

	// ── Plausible ──────────────────────────────────────────────────────────
	"plausible_secret_key_base": "plausible",

	// ── PostgreSQL ─────────────────────────────────────────────────────────
	"postgres_password": "postgres",
	"pgpassword":        "postgres",

	// ── PostHog ────────────────────────────────────────────────────────────
	"posthog_secret_key": "posthog",

	// ── Rails (generic) ────────────────────────────────────────────────────
	"rails_master_key": "rails",
	"secret_key_base":  "rails", // Phoenix/Elixir also uses this

	// ── Redis / Valkey ─────────────────────────────────────────────────────
	"redis_password":  "redis",
	"requirepass":     "redis",
	"valkey_password": "valkey",

	// ── Sentry ─────────────────────────────────────────────────────────────
	"sentry_secret_key": "sentry",

	// ── Strapi ─────────────────────────────────────────────────────────────
	"app_keys":            "strapi",
	"api_token_salt":      "strapi",
	"admin_jwt_secret":    "strapi",
	"transfer_token_salt": "strapi",

	// ── Supabase ───────────────────────────────────────────────────────────
	"supabase_jwt_secret":       "supabase",
	"dashboard_password":        "supabase",
	"supabase_anon_key":         "supabase",
	"supabase_service_role_key": "supabase",

	// ── Umami ──────────────────────────────────────────────────────────────
	"app_secret": "umami",
	"hash_salt":  "umami",

	// ── Vaultwarden ────────────────────────────────────────────────────────
	"admin_token":             "vaultwarden",
	"vaultwarden_admin_token": "vaultwarden",

	// ── WordPress ──────────────────────────────────────────────────────────
	"auth_key":         "wordpress",
	"secure_auth_key":  "wordpress",
	"logged_in_key":    "wordpress",
	"nonce_key":        "wordpress",
	"auth_salt":        "wordpress",
	"secure_auth_salt": "wordpress",
	"logged_in_salt":   "wordpress",
	"nonce_salt":       "wordpress",
}

// LookupWellKnown checks the well-known keys catalog for an exact match
// (case-insensitive). If the key is found, it returns ("generated", project, true).
// If not found, it returns ("", "", false).
//
// All keys in the catalog are auto-rotatable internal secrets.
func LookupWellKnown(keyName string) (mode string, project string, ok bool) {
	lower := strings.ToLower(keyName)
	if proj, found := wellKnownGenerated[lower]; found {
		return "generated", proj, true
	}
	return "", "", false
}
