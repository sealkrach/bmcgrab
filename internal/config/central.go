package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Central is the runtime configuration shared by all collectors. It is stored
// in the `config` table (one JSON document, versioned) and edited from the web
// UI. Collectors re-read it at the start of every cycle and keep a local JSON
// cache so they can keep running if the database is unreachable.
type Central struct {
	Version int       `json:"version"`
	Updated time.Time `json:"updated_at"`
	Author  string    `json:"author"`

	Collect struct {
		Interval time.Duration `json:"interval"`
		Workers  int           `json:"workers"`
		Timeout  time.Duration `json:"timeout"`
		Retries  int           `json:"retries"`
	} `json:"collect"`

	Breaker struct {
		Failures uint32        `json:"failures"`
		Cooldown time.Duration `json:"cooldown"`
	} `json:"breaker"`

	Metrics struct {
		Enabled []string `json:"enabled"` // cpu, memory, thermal, power
	} `json:"metrics"`

	Quality struct {
		TempMinC     float64       `json:"temp_min_c"`
		TempMaxC     float64       `json:"temp_max_c"`
		PowerMinW    float64       `json:"power_min_w"`
		PowerMaxW    float64       `json:"power_max_w"`
		MaxClockSkew time.Duration `json:"max_clock_skew"`
	} `json:"quality"`

	Inventory struct {
		Type    string        `json:"type"` // sql | rest | csv
		Refresh time.Duration `json:"refresh"`
		SQL     struct {
			DSN         string `json:"dsn"`
			PasswordEnv string `json:"password_env"`
			Query       string `json:"query"`
		} `json:"sql"`
		REST struct {
			URL      string `json:"url"`
			JSONPath string `json:"json_path"`
			TokenEnv string `json:"token_env"`
		} `json:"rest"`
		CSV struct {
			Path string `json:"path"`
		} `json:"csv"`
	} `json:"inventory"`

	TLS struct {
		InsecureSkipVerify bool `json:"insecure_skip_verify"`
	} `json:"tls"`
}

// Default returns sane production defaults; used on first migration and as a
// fallback when neither the database nor the local cache can be read.
func Default() *Central {
	c := &Central{Version: 0, Updated: time.Now().UTC(), Author: "default"}
	c.Collect.Interval = 5 * time.Minute
	c.Collect.Workers = 50
	c.Collect.Timeout = 20 * time.Second
	c.Collect.Retries = 2
	c.Breaker.Failures = 5
	c.Breaker.Cooldown = 15 * time.Minute
	c.Metrics.Enabled = []string{"cpu", "memory", "thermal", "power"}
	c.Quality.TempMinC = -10
	c.Quality.TempMaxC = 150
	c.Quality.PowerMinW = 0
	c.Quality.PowerMaxW = 20000
	c.Quality.MaxClockSkew = 5 * time.Minute
	c.Inventory.Type = "csv"
	c.Inventory.Refresh = 5 * time.Minute
	c.Inventory.CSV.Path = "/etc/bmcgrab/inventory.csv"
	c.Inventory.SQL.Query = "SELECT id, hostname, bmc_ip, region, vendor FROM servers WHERE active"
	c.Inventory.REST.JSONPath = "servers"
	return c
}

// Validate rejects values that would make a collector misbehave.
func (c *Central) Validate() error {
	switch {
	case c.Collect.Interval < 30*time.Second:
		return fmt.Errorf("collect.interval must be >= 30s")
	case c.Collect.Workers < 1 || c.Collect.Workers > 1000:
		return fmt.Errorf("collect.workers must be between 1 and 1000")
	case c.Collect.Timeout < time.Second:
		return fmt.Errorf("collect.timeout must be >= 1s")
	case c.Quality.TempMinC >= c.Quality.TempMaxC:
		return fmt.Errorf("quality.temp range is empty")
	case c.Quality.PowerMinW >= c.Quality.PowerMaxW:
		return fmt.Errorf("quality.power range is empty")
	case c.Inventory.Type != "sql" && c.Inventory.Type != "rest" && c.Inventory.Type != "csv":
		return fmt.Errorf("inventory.type must be sql, rest or csv")
	}
	return nil
}

// MetricEnabled reports whether a metric family is turned on.
func (c *Central) MetricEnabled(name string) bool {
	for _, m := range c.Metrics.Enabled {
		if m == name {
			return true
		}
	}
	return false
}

// SaveCache writes the central config to the local cache file (0600).
func (c *Central) SaveCache(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadCache reads the local cache file.
func LoadCache(path string) (*Central, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Central
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config cache: %w", err)
	}
	return &c, nil
}
