// Package bmcgrab exposes repository-level embedded assets.
package bmcgrab

import "embed"

// Migrations holds the SQL files applied by `bmcgrab migrate`.
//
//go:embed migrations/*.sql
var Migrations embed.FS
