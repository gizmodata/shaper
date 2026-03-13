// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/apache/arrow-go/v18/arrow/flight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// DiscoverOAuthURL connects to a GizmoSQL server via Flight handshake
// with the magic username "__discover__" and reads the OAuth URL from
// the "x-gizmosql-oauth-url" response header.
func DiscoverOAuthURL(ctx context.Context, conn Connection) (string, error) {
	addr := fmt.Sprintf("%s:%d", conn.Host, conn.Port)

	var creds grpc.DialOption
	if conn.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: conn.SkipVerify,
		}
		creds = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	} else {
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	client, err := flight.NewClientWithMiddleware(addr, nil, nil, creds)
	if err != nil {
		return "", fmt.Errorf("failed to create Flight client: %w", err)
	}
	defer client.Close()

	// Send handshake with username="__discover__" via Basic Auth
	authCtx := metadata.AppendToOutgoingContext(ctx,
		"authorization", "Basic X19kaXNjb3Zlcl9fOg==") // base64("__discover__:")

	stream, err := client.Handshake(authCtx)
	if err != nil {
		return "", fmt.Errorf("handshake failed: %w", err)
	}

	if err := stream.CloseSend(); err != nil {
		return "", fmt.Errorf("failed to close send: %w", err)
	}

	header, err := stream.Header()
	if err != nil {
		return "", fmt.Errorf("failed to get headers: %w", err)
	}

	// Drain the stream
	for {
		_, err := stream.Recv()
		if err != nil {
			break
		}
	}

	trailer := stream.Trailer()
	md := metadata.Join(header, trailer)

	urls := md.Get("x-gizmosql-oauth-url")
	if len(urls) == 0 || urls[0] == "" {
		return "", fmt.Errorf("server does not support OAuth (no x-gizmosql-oauth-url header)")
	}

	return urls[0], nil
}

type OAuthInitiateResponse struct {
	SessionUUID string `json:"session_uuid"`
	AuthURL     string `json:"auth_url"`
}

// OAuthInitiate calls the OAuth server's /oauth/initiate endpoint
// and returns the session UUID and auth URL for the user to complete login.
func OAuthInitiate(ctx context.Context, oauthBaseURL string) (*OAuthInitiateResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", oauthBaseURL+"/oauth/initiate", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call OAuth initiate: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OAuth initiate returned %d: %s", resp.StatusCode, string(body))
	}

	var result OAuthInitiateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse OAuth initiate response: %w", err)
	}

	return &result, nil
}

type OAuthTokenResponse struct {
	Status string `json:"status"`
	Token  string `json:"token"`
	Error  string `json:"error,omitempty"`
}

// OAuthPollToken polls the OAuth server's /oauth/token/:session_uuid endpoint
// for the identity token after the user completes login.
func OAuthPollToken(ctx context.Context, oauthBaseURL, sessionUUID string) (string, error) {
	url := oauthBaseURL + "/oauth/token/" + sessionUUID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to poll OAuth token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var result OAuthTokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse OAuth token response (status %d): %s", resp.StatusCode, string(body))
	}

	switch result.Status {
	case "complete":
		if result.Token == "" {
			return "", fmt.Errorf("OAuth complete but token is empty")
		}
		return result.Token, nil
	case "pending":
		return "", fmt.Errorf("OAuth token pending")
	case "error":
		return "", fmt.Errorf("OAuth error: %s", result.Error)
	case "not_found":
		return "", fmt.Errorf("OAuth session not found (url: %s)", url)
	default:
		return "", fmt.Errorf("unexpected OAuth status %q (HTTP %d): %s", result.Status, resp.StatusCode, string(body))
	}
}

// OAuthCompleteConnection discovers OAuth URL, initiates the flow, and returns
// the auth URL for the user. After the user completes login, call OAuthFinalize
// to poll for the token and update the connection.
func OAuthStartFlow(app *App, ctx context.Context, connID string) (string, string, string, error) {
	var conn Connection
	err := app.Sqlite.GetContext(ctx, &conn,
		`SELECT id, name, host, port, username, password_encrypted, use_tls, skip_verify, status, created_at, updated_at
		 FROM connections WHERE id = $1`, connID)
	if err != nil {
		return "", "", "", fmt.Errorf("connection not found: %w", err)
	}

	oauthURL, err := DiscoverOAuthURL(ctx, conn)
	if err != nil {
		return "", "", "", err
	}
	slog.Info("OAuth: discovered OAuth URL", "oauthURL", oauthURL, "connID", connID)

	initResp, err := OAuthInitiate(ctx, oauthURL)
	if err != nil {
		return "", "", "", err
	}
	slog.Info("OAuth: initiated flow", "sessionUUID", initResp.SessionUUID, "authURL", initResp.AuthURL)

	return oauthURL, initResp.SessionUUID, initResp.AuthURL, nil
}

// OAuthFinalize polls for the token and updates the connection's username/password.
func OAuthFinalize(app *App, ctx context.Context, connID, oauthBaseURL, sessionUUID string) error {
	token, err := OAuthPollToken(ctx, oauthBaseURL, sessionUUID)
	if err != nil {
		return err
	}

	// Encrypt the token as the new password
	encrypted, err := encryptPassword(token, app.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
	}

	actor := ActorFromContext(ctx)
	actorStr := ""
	if actor != nil {
		actorStr = actor.String()
	}

	// Update only username and password fields
	_, err = app.Sqlite.ExecContext(ctx,
		`UPDATE connections SET username = 'token', password_encrypted = $1, updated_at = $2, updated_by = $3 WHERE id = $4`,
		encrypted, time.Now(), actorStr, connID)
	if err != nil {
		return fmt.Errorf("failed to update connection credentials: %w", err)
	}

	// Evict from pool so next use picks up new credentials
	if app.ConnPool != nil {
		app.ConnPool.Evict(connID)
	}

	return nil
}
