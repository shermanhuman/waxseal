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
