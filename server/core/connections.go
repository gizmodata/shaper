// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/nrednav/cuid2"
)

type Connection struct {
	ID                string    `db:"id" json:"id"`
	Name              string    `db:"name" json:"name"`
	Host              string    `db:"host" json:"host"`
	Port              int       `db:"port" json:"port"`
	Username          string    `db:"username" json:"username"`
	PasswordEncrypted string    `db:"password_encrypted" json:"-"`
	UseTLS            bool      `db:"use_tls" json:"useTls"`
	SkipVerify        bool      `db:"skip_verify" json:"skipVerify"`
	Status            string    `db:"status" json:"status"`
	CreatedAt         time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt         time.Time `db:"updated_at" json:"updatedAt"`
	CreatedBy         *string   `db:"created_by" json:"createdBy,omitempty"`
	UpdatedBy         *string   `db:"updated_by" json:"updatedBy,omitempty"`
}

type ConnectionListResult struct {
	Connections []Connection `json:"connections"`
}

type CreateConnectionPayload struct {
	ID                string    `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	Name              string    `json:"name"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Username          string    `json:"username"`
	PasswordEncrypted string    `json:"passwordEncrypted"`
	UseTLS            bool      `json:"useTls"`
	SkipVerify        bool      `json:"skipVerify"`
	CreatedBy         string    `json:"createdBy"`
}

type UpdateConnectionPayload struct {
	ID                string    `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	Name              string    `json:"name"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Username          string    `json:"username"`
	PasswordEncrypted string    `json:"passwordEncrypted"`
	UseTLS            bool      `json:"useTls"`
	SkipVerify        bool      `json:"skipVerify"`
	UpdatedBy         string    `json:"updatedBy"`
}

type DeleteConnectionPayload struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	DeletedBy string    `json:"deletedBy"`
}

type UpdateConnectionStatusPayload struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	UpdatedBy string    `json:"updatedBy"`
}

type UpdateDashboardConnectionPayload struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ConnectionID *string   `json:"connectionId"`
	UpdatedBy    string    `json:"updatedBy"`
}

func ListConnections(app *App, ctx context.Context) (ConnectionListResult, error) {
	connections := []Connection{}
	err := app.Sqlite.SelectContext(ctx, &connections,
		`SELECT id, name, host, port, username, password_encrypted, use_tls, skip_verify, status, created_at, updated_at, created_by, updated_by
		 FROM connections
		 ORDER BY created_at DESC`)
	if err != nil {
		err = fmt.Errorf("error listing connections: %w", err)
	}
	return ConnectionListResult{Connections: connections}, err
}

func CreateConnection(app *App, ctx context.Context, name, host string, port int, username, password string, useTLS, skipVerify bool) (string, error) {
	actor := ActorFromContext(ctx)
	if actor == nil {
		return "", fmt.Errorf("no actor in context")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("connection name is required")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("host is required")
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid port number")
	}

	encrypted, err := encryptPassword(password, app.JWTSecret)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt password: %w", err)
	}

	id := cuid2.Generate()
	payload := CreateConnectionPayload{
		ID:                id,
		Timestamp:         time.Now(),
		Name:              name,
		Host:              host,
		Port:              port,
		Username:          username,
		PasswordEncrypted: encrypted,
		UseTLS:            useTLS,
		SkipVerify:        skipVerify,
		CreatedBy:         actor.String(),
	}
	err = app.SubmitState(ctx, "create_connection", payload)
	return id, err
}

func UpdateConnection(app *App, ctx context.Context, id, name, host string, port int, username, password string, useTLS, skipVerify bool) error {
	actor := ActorFromContext(ctx)
	if actor == nil {
		return fmt.Errorf("no actor in context")
	}
	var count int
	err := app.Sqlite.GetContext(ctx, &count, `SELECT COUNT(*) FROM connections WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to query connection: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("connection not found")
	}

	encrypted, err := encryptPassword(password, app.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}

	payload := UpdateConnectionPayload{
		ID:                id,
		Timestamp:         time.Now(),
		Name:              strings.TrimSpace(name),
		Host:              strings.TrimSpace(host),
		Port:              port,
		Username:          username,
		PasswordEncrypted: encrypted,
		UseTLS:            useTLS,
		SkipVerify:        skipVerify,
		UpdatedBy:         actor.String(),
	}
	err = app.SubmitState(ctx, "update_connection", payload)
	if err != nil {
		return fmt.Errorf("failed to submit connection update: %w", err)
	}
	if app.ConnPool != nil {
		app.ConnPool.Evict(id)
	}
	return nil
}

func DeleteConnection(app *App, ctx context.Context, id string) error {
	actor := ActorFromContext(ctx)
	if actor == nil {
		return fmt.Errorf("no actor in context")
	}
	var count int
	err := app.Sqlite.GetContext(ctx, &count, `SELECT COUNT(*) FROM connections WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to query connection: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("connection not found")
	}
	err = app.SubmitState(ctx, "delete_connection", DeleteConnectionPayload{
		ID:        id,
		Timestamp: time.Now(),
		DeletedBy: actor.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to submit connection deletion: %w", err)
	}
	if app.ConnPool != nil {
		app.ConnPool.Evict(id)
	}
	return nil
}

func TestConnection(app *App, ctx context.Context, id string) error {
	var conn Connection
	err := app.Sqlite.GetContext(ctx, &conn,
		`SELECT id, name, host, port, username, password_encrypted, use_tls, skip_verify, status, created_at, updated_at
		 FROM connections WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("connection not found: %w", err)
	}
	password, err := decryptPassword(conn.PasswordEncrypted, app.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt password: %w", err)
	}
	db, err := openFlightSQLConnection(conn, password)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	return nil
}

func SaveDashboardConnection(app *App, ctx context.Context, dashboardID string, connectionID *string) error {
	actor := ActorFromContext(ctx)
	if actor == nil {
		return fmt.Errorf("no actor in context")
	}
	var count int
	err := app.Sqlite.GetContext(ctx, &count, `SELECT COUNT(*) FROM apps WHERE id = $1 AND type = 'dashboard'`, dashboardID)
	if err != nil {
		return fmt.Errorf("failed to query dashboard: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("dashboard not found")
	}
	if connectionID != nil && *connectionID != "" {
		err = app.Sqlite.GetContext(ctx, &count, `SELECT COUNT(*) FROM connections WHERE id = $1`, *connectionID)
		if err != nil {
			return fmt.Errorf("failed to query connection: %w", err)
		}
		if count == 0 {
			return fmt.Errorf("connection not found")
		}
	}
	err = app.SubmitState(ctx, "update_dashboard_connection", UpdateDashboardConnectionPayload{
		ID:           dashboardID,
		Timestamp:    time.Now(),
		ConnectionID: connectionID,
		UpdatedBy:    actor.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to submit dashboard connection update: %w", err)
	}
	return nil
}

// State handlers

func HandleCreateConnection(app *App, data []byte) bool {
	var payload CreateConnectionPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		app.Logger.Error("failed to unmarshal create connection payload", slog.Any("error", err))
		return false
	}
	_, err := app.Sqlite.Exec(
		`INSERT OR IGNORE INTO connections (
			id, name, host, port, username, password_encrypted, use_tls, skip_verify, status, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $9, $10, $10)`,
		payload.ID, payload.Name, payload.Host, payload.Port, payload.Username,
		payload.PasswordEncrypted, payload.UseTLS, payload.SkipVerify,
		payload.Timestamp, payload.CreatedBy,
	)
	if err != nil {
		app.Logger.Error("failed to insert connection into DB", slog.Any("error", err))
		return false
	}
	return true
}

func HandleUpdateConnection(app *App, data []byte) bool {
	var payload UpdateConnectionPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		app.Logger.Error("failed to unmarshal update connection payload", slog.Any("error", err))
		return false
	}
	_, err := app.Sqlite.Exec(
		`UPDATE connections
		 SET name = $1, host = $2, port = $3, username = $4, password_encrypted = $5, use_tls = $6, skip_verify = $7, updated_at = $8, updated_by = $9
		 WHERE id = $10`,
		payload.Name, payload.Host, payload.Port, payload.Username,
		payload.PasswordEncrypted, payload.UseTLS, payload.SkipVerify,
		payload.Timestamp, payload.UpdatedBy, payload.ID,
	)
	if err != nil {
		app.Logger.Error("failed to execute UPDATE statement for connection", slog.Any("error", err))
		return false
	}
	return true
}

func HandleDeleteConnection(app *App, data []byte) bool {
	var payload DeleteConnectionPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		app.Logger.Error("failed to unmarshal delete connection payload", slog.Any("error", err))
		return false
	}
	_, err := app.Sqlite.Exec(`DELETE FROM connections WHERE id = $1`, payload.ID)
	if err != nil {
		app.Logger.Error("failed to execute DELETE statement for connection", slog.Any("error", err))
		return false
	}
	return true
}

func HandleUpdateConnectionStatus(app *App, data []byte) bool {
	var payload UpdateConnectionStatusPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		app.Logger.Error("failed to unmarshal update connection status payload", slog.Any("error", err))
		return false
	}
	_, err := app.Sqlite.Exec(
		`UPDATE connections SET status = $1, updated_at = $2, updated_by = $3 WHERE id = $4`,
		payload.Status, payload.Timestamp, payload.UpdatedBy, payload.ID,
	)
	if err != nil {
		app.Logger.Error("failed to execute UPDATE statement for connection status", slog.Any("error", err))
		return false
	}
	return true
}

func HandleUpdateDashboardConnection(app *App, data []byte) bool {
	var payload UpdateDashboardConnectionPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		app.Logger.Error("failed to unmarshal update dashboard connection payload", slog.Any("error", err))
		return false
	}
	_, err := app.Sqlite.Exec(
		`UPDATE apps SET connection_id = $1, updated_at = $2, updated_by = $3 WHERE id = $4 AND type = 'dashboard'`,
		payload.ConnectionID, payload.Timestamp, payload.UpdatedBy, payload.ID,
	)
	if err != nil {
		app.Logger.Error("failed to execute UPDATE statement for dashboard connection", slog.Any("error", err))
		return false
	}
	return true
}

// Password encryption helpers using AES-GCM keyed from JWTSecret

func encryptPassword(plaintext string, key []byte) (string, error) {
	hash := sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptPassword(ciphertextB64 string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	hash := sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(plaintext), nil
}
