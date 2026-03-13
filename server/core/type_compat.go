// SPDX-License-Identifier: MPL-2.0

package core

import (
	"regexp"
	"strings"

	"github.com/duckdb/duckdb-go/v2"
)

var sparseUnionMemberRe = regexp.MustCompile(`(\w+): type=`)
var unionMemberRe = regexp.MustCompile(`"(\w+)"`)

// matchesDefinition returns true if a database type name matches a Shaper type definition.
// For local DuckDB, type names match definitions exactly (e.g. UNION("xaxis_varchar" VARCHAR)).
// For remote connections via ADBC/Arrow Flight SQL, UNION types arrive as
// sparse_union<member_name: type=X, nullable=N, ...> — this function matches by comparing
// the member names from both formats.
func matchesDefinition(dbTypeName, definition string) bool {
	if dbTypeName == definition {
		return true
	}
	if !strings.HasPrefix(dbTypeName, "sparse_union<") {
		return false
	}
	remoteMembers := parseSparseUnionMembers(dbTypeName)
	localMembers := parseUnionMembers(definition)
	if len(remoteMembers) != len(localMembers) {
		return false
	}
	for i, m := range remoteMembers {
		if m != localMembers[i] {
			return false
		}
	}
	return true
}

// parseSparseUnionMembers extracts member names from an Arrow sparse_union type string.
// Format: sparse_union<member1: type=utf8, nullable=false, member2: type=double, nullable=false>
func parseSparseUnionMembers(sparseUnion string) []string {
	matches := sparseUnionMemberRe.FindAllStringSubmatch(sparseUnion, -1)
	members := make([]string, 0, len(matches))
	for _, match := range matches {
		members = append(members, match[1])
	}
	return members
}

// parseUnionMembers extracts member names from a DuckDB UNION type definition.
// Format: UNION("member1" VARCHAR, "member2" TIMESTAMP)
func parseUnionMembers(definition string) []string {
	matches := unionMemberRe.FindAllStringSubmatch(definition, -1)
	members := make([]string, 0, len(matches))
	for _, match := range matches {
		members = append(members, match[1])
	}
	return members
}

// unwrapValue extracts the inner value from a duckdb.Union, or returns
// the value as-is for remote connections where values arrive as plain Go types.
func unwrapValue(v any) any {
	if v == nil {
		return nil
	}
	if u, ok := v.(duckdb.Union); ok {
		return u.Value
	}
	return v
}

// unwrapTag returns the union tag if the value is a duckdb.Union,
// or empty string for plain values from remote connections.
func unwrapTag(v any) string {
	if u, ok := v.(duckdb.Union); ok {
		return u.Tag
	}
	return ""
}
