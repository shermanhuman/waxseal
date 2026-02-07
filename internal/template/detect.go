package template

import (
	"net/url"
	"strings"
)

// DetectConnectionString checks if a value is a database/service connection string
// and returns a template with {{variable}} placeholders and the extracted values.
// allKeys is the list of other key names in the same secret (for future cross-referencing).
func DetectConnectionString(value string, allKeys []string) (isTemplate bool, tmpl string, values map[string]string) {
	// Check if it looks like a URL-based connection string
	if !strings.Contains(value, "://") {
		return false, "", nil
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return false, "", nil
	}

	// Common database/service connection string schemes
	schemes := []string{
		// SQL Databases
		"postgresql", "postgres", "mysql", "mariadb", "sqlserver", "mssql",
		// NoSQL Databases
		"mongodb", "mongodb+srv", "couchbase", "couchdb", "cockroachdb",
		// Key-Value / Cache
		"redis", "rediss", "memcached",
		// Message Queues
		"amqp", "amqps", "nats", "tls", "kafka",
		// Search
		"elasticsearch", "opensearch",
		// Other
		"clickhouse", "cassandra", "scylla", "neo4j", "bolt",
	}
	isDBConnection := false
	for _, s := range schemes {
		if strings.EqualFold(parsed.Scheme, s) {
			isDBConnection = true
			break
		}
	}
	if !isDBConnection {
		return false, "", nil
	}

	// Extract values and build template
	values = make(map[string]string)
	tmpl = value

	// Extract username and password (password becomes {{secret}})
	if parsed.User != nil {
		if username := parsed.User.Username(); username != "" {
			values["username"] = username
			tmpl = strings.Replace(tmpl, username, "{{username}}", 1)
		}
		if password, ok := parsed.User.Password(); ok && password != "" {
			// Password is the secret - use {{secret}} as standard variable
			tmpl = strings.Replace(tmpl, password, "{{secret}}", 1)
		}
	}

	// Extract host and port
	if parsed.Host != "" {
		host := parsed.Hostname()
		port := parsed.Port()

		if host != "" {
			values["host"] = host
			// Replace host in template carefully (it may appear after @)
			tmpl = strings.Replace(tmpl, host, "{{host}}", 1)
		}
		if port != "" {
			values["port"] = port
			tmpl = strings.Replace(tmpl, ":"+port, ":{{port}}", 1)
		}
	}

	// Extract database name from path
	if parsed.Path != "" && parsed.Path != "/" {
		database := strings.TrimPrefix(parsed.Path, "/")
		if database != "" {
			values["database"] = database
			tmpl = strings.Replace(tmpl, "/"+database, "/{{database}}", 1)
		}
	}

	return true, tmpl, values
}

// SuggestKeyType analyzes a key's value and suggests if it should be templated.
// Returns suggestedType ("standalone" or "templated"), a template string if applicable,
// and the extracted values.
func SuggestKeyType(keyName string, value string, allKeys []string) (suggestedType string, suggestedTemplate string, extractedValues map[string]string) {
	// Check for common templated key names
	templateKeyPatterns := []string{"url", "uri", "connection", "dsn"}
	keyLower := strings.ToLower(keyName)
	mightBeTemplated := false
	for _, pattern := range templateKeyPatterns {
		if strings.Contains(keyLower, pattern) {
			mightBeTemplated = true
			break
		}
	}

	if !mightBeTemplated {
		return "standalone", "", nil
	}

	// Try to detect if it's a connection string
	isTemplate, tmpl, values := DetectConnectionString(value, allKeys)
	if isTemplate {
		return "templated", tmpl, values
	}

	return "standalone", "", nil
}

// SuggestRotationMode infers a rotation mode from a key name using heuristics.
// Returns one of: "generated", "external", "static", "computed", or "unknown".
//
// This is used by the discover wizard to pre-select keys for batch auto-generation,
// saving operators from configuring each key individually.
func SuggestRotationMode(keyName string) string {
	// Check well-known keys catalog first (catches camelCase / non-standard names)
	if mode, _, ok := LookupWellKnown(keyName); ok {
		return mode
	}

	lower := strings.ToLower(keyName)

	// Computed / templated keys (connection strings, URLs)
	for _, p := range []string{"_url", "_uri", "_dsn", "database_url", "redis_url"} {
		if strings.HasSuffix(lower, p) || lower == strings.TrimPrefix(p, "_") {
			return "computed"
		}
	}

	// Generated keys — passwords and secret material
	generatedPatterns := []string{
		"password", "passwd", "secret_key_base", "secret_key",
		"encryption_key", "signing_key", "master_key",
		"webhook_secret", "hmac_secret",
	}
	for _, p := range generatedPatterns {
		if lower == p || strings.HasSuffix(lower, "_"+p) || strings.HasPrefix(lower, p+"_") {
			return "generated"
		}
	}
	// Suffix-based: ends with _password, _token, _secret (but not client_secret / oauth)
	for _, suffix := range []string{"_password", "_token", "_secret"} {
		if strings.HasSuffix(lower, suffix) {
			// Exclude vendor-managed secrets that are typically external
			if strings.Contains(lower, "client") || strings.Contains(lower, "oauth") || strings.Contains(lower, "api_key") {
				return "external"
			}
			return "generated"
		}
	}
	// Exact matches for common generated names
	for _, exact := range []string{"rootpassword", "rootpass"} {
		if strings.ReplaceAll(lower, "_", "") == exact {
			return "generated"
		}
	}

	// External keys — vendor-managed credentials
	externalPatterns := []string{
		"client_id", "client_secret", "api_key", "api_secret",
		"oauth", "access_key", "secret_access_key",
		".dockerconfigjson",
	}
	for _, p := range externalPatterns {
		if lower == p || strings.Contains(lower, p) {
			return "external"
		}
	}

	// Static keys — identifiers and config that rarely change
	staticPatterns := []string{
		"username", "user", "email", "host", "port", "database", "dbname",
		"region", "bucket", "endpoint",
	}
	for _, p := range staticPatterns {
		if lower == p || strings.HasSuffix(lower, "_"+p) {
			return "static"
		}
	}

	return "unknown"
}
