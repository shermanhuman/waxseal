package gcp

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
)

// ADCTokenValid attempts to fetch a token from Application Default Credentials.
// Returns nil if a valid token can be obtained, or an error describing why not.
//
// This goes beyond ADCExists() — it catches expired/revoked tokens (invalid_grant)
// that cause runtime failures like "reauth related error (invalid_rapt)".
func ADCTokenValid(ctx context.Context) error {
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("find credentials: %w", err)
	}

	_, err = creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("obtain token: %w", err)
	}

	return nil
}
