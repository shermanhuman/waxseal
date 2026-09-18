package computed

import (
	"net/url"
	"strings"
)

var connectionSchemes = []string{
	// SQL
	"postgresql", "postgres", "mysql", "mariadb", "sqlserver", "mssql",
	// NoSQL
	"mongodb", "mongodb+srv", "couchbase", "couchdb", "cockroachdb",
	// Key-value / cache
	"redis", "rediss", "memcached",
	// Messaging
	"amqp", "amqps", "nats", "tls", "kafka",
	// Search
	"elasticsearch", "opensearch",
	// Other
	"clickhouse", "cassandra", "scylla", "neo4j", "bolt",
}

// DetectConnectionString recognises a database-style URL with a password and
// splits it into a template, its non-secret values and the password. The
// template is rebuilt from the URL's parts rather than by substitution, so a
// password that is percent-encoded, or that happens to appear elsewhere in
// the URL, can never leak into the template. The password is returned in
// its raw (encoded) form so that rendering the template reproduces the
// original value exactly.
func DetectConnectionString(value string) (tmpl string, values map[string]string, secret string, ok bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return "", nil, "", false
	}
	scheme := parsed.Scheme
	known := false
	for _, s := range connectionSchemes {
		if strings.EqualFold(scheme, s) {
			known = true
			break
		}
	}
	if !known {
		return "", nil, "", false
	}

	// Raw parts: authority is everything between "://" and the first
	// '/', '?' or '#'; userinfo is up to the last '@' in it.
	rest := value[len(scheme)+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return "", nil, "", false
	}
	userinfo := authority[:at]
	rawUser, rawPassword, hasPassword := strings.Cut(userinfo, ":")
	if !hasPassword || rawPassword == "" {
		return "", nil, "", false
	}

	values = map[string]string{}
	var b strings.Builder
	b.WriteString(scheme + "://")
	if rawUser != "" {
		values["username"] = rawUser
		b.WriteString("{{username}}")
	}
	b.WriteString(":{{secret}}@")

	host, port := parsed.Hostname(), parsed.Port()
	switch {
	case host == "" || strings.Contains(host, ":"):
		// No host, or an IPv6 literal: keep the raw host:port as is.
		b.WriteString(authority[at+1:])
	default:
		values["host"] = host
		b.WriteString("{{host}}")
		if port != "" {
			values["port"] = port
			b.WriteString(":{{port}}")
		}
	}

	if strings.HasPrefix(tail, "/") {
		pathEnd := strings.IndexAny(tail, "?#")
		if pathEnd < 0 {
			pathEnd = len(tail)
		}
		if database := tail[1:pathEnd]; database != "" {
			values["database"] = database
			b.WriteString("/{{database}}")
			tail = tail[pathEnd:]
		}
	}
	b.WriteString(tail)
	tmpl = b.String()

	// The template must reproduce the value, and the password must not
	// survive in the only literal part that could carry it (the query and
	// fragment); the scheme is a fixed public word.
	p := &Payload{Template: tmpl, Values: values, Secret: rawPassword}
	if rendered, err := p.Compute(); err != nil || rendered != value || strings.Contains(tail, rawPassword) {
		return "", nil, "", false
	}
	return tmpl, values, rawPassword, true
}
