// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/apache/arrow-adbc/go/adbc/driver/flightsql"
	"github.com/apache/arrow-adbc/go/adbc/sqldriver"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/jmoiron/sqlx"
)

type ConnectionPool struct {
	mu   sync.RWMutex
	pool map[string]*sqlx.DB
	app  *App
}

func NewConnectionPool(app *App) *ConnectionPool {
	return &ConnectionPool{
		pool: make(map[string]*sqlx.DB),
		app:  app,
	}
}

// GetDB returns the database connection pool for the given connection ID.
// When connectionID is nil or empty, returns the local DuckDB pool.
// Otherwise, returns a cached or newly opened ADBC Flight SQL connection pool.
func (p *ConnectionPool) GetDB(ctx context.Context, connectionID *string) (*sqlx.DB, error) {
	if connectionID == nil || *connectionID == "" {
		return p.app.DuckDB, nil
	}

	id := *connectionID

	p.mu.RLock()
	if db, ok := p.pool[id]; ok {
		p.mu.RUnlock()
		return db, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if db, ok := p.pool[id]; ok {
		return db, nil
	}

	var conn Connection
	err := p.app.Sqlite.GetContext(ctx, &conn,
		`SELECT id, name, host, port, username, password_encrypted, use_tls, skip_verify, status, created_at, updated_at
		 FROM connections WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("connection not found: %w", err)
	}

	password, err := decryptPassword(conn.PasswordEncrypted, p.app.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt password: %w", err)
	}

	sqlxDB, err := openFlightSQLConnection(conn, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open Flight SQL connection: %w", err)
	}

	// Bootstrap Shaper custom types on the remote DuckDB
	for _, t := range dbTypes {
		if err := createType(sqlxDB, t.Name, t.Definition); err != nil {
			sqlxDB.Close()
			return nil, fmt.Errorf("failed to create type %s on remote: %w", t.Name, err)
		}
	}
	if err := createBoxlotFunction(sqlxDB); err != nil {
		sqlxDB.Close()
		return nil, fmt.Errorf("failed to create BOXPLOT function on remote: %w", err)
	}

	p.pool[id] = sqlxDB
	return sqlxDB, nil
}

// Evict removes a connection from the pool and closes it.
func (p *ConnectionPool) Evict(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if db, ok := p.pool[id]; ok {
		db.Close()
		delete(p.pool, id)
	}
}

// Close closes all pooled connections.
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, db := range p.pool {
		db.Close()
		delete(p.pool, id)
	}
}

func openFlightSQLConnection(conn Connection, password string) (*sqlx.DB, error) {
	scheme := "grpc"
	if conn.UseTLS {
		scheme = "grpc+tls"
	}
	uri := fmt.Sprintf("%s://%s:%d", scheme, conn.Host, conn.Port)

	// Build semicolon-separated DSN for the sqldriver
	var parts []string
	parts = append(parts, "uri="+uri)
	if conn.Username != "" {
		parts = append(parts, "username="+conn.Username)
	}
	if password != "" {
		parts = append(parts, "password="+password)
	}
	if conn.SkipVerify {
		parts = append(parts, "adbc.flight.sql.client_option.tls_skip_verify=true")
	}
	dsn := strings.Join(parts, ";")

	drv := sqldriver.Driver{
		Driver: flightsql.NewDriver(memory.DefaultAllocator),
	}
	connector, err := drv.OpenConnector(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}
	db := sql.OpenDB(connector)

	return sqlx.NewDb(db, "flightsql"), nil
}
