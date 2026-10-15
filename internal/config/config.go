// Package config loads the minimal local configuration of a bmcgrab instance
// (identity + connections) and the central runtime configuration stored in
// the database. The local file is deliberately tiny: everything that an
// operator may want to tune lives in the central config and is editable from
// the web UI without restarting the collectors.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Local is what a collector or server reads from its YAML file (or env vars).
type Local struct {
	Region string `mapstructure:"region"`

	Database struct {
		DSN         string `mapstructure:"dsn"`
		PasswordEnv string `mapstructure:"password_env"`
	} `mapstructure:"database"`

	CyberArk struct {
		URL        string        `mapstructure:"url"`
		AppID      string        `mapstructure:"app_id"`
		Safe       string        `mapstructure:"safe"`
		Object     string        `mapstructure:"object"`
		ClientCert string        `mapstructure:"client_cert"`
		ClientKey  string        `mapstructure:"client_key"`
		CAFile     string        `mapstructure:"ca_file"`
		CacheTTL   time.Duration `mapstructure:"cache_ttl"`
	} `mapstructure:"cyberark"`

	// Lab-only fallback when no CyberArk is reachable: credentials from env.
	// Refused unless --lab is passed.
	LabCredentials struct {
		UsernameEnv string `mapstructure:"username_env"`
		PasswordEnv string `mapstructure:"password_env"`
	} `mapstructure:"lab_credentials"`

	TLS struct {
		CAFile string `mapstructure:"ca_file"`
	} `mapstructure:"tls"`

	Local struct {
		BufferDir   string `mapstructure:"buffer_dir"`
		ConfigCache string `mapstructure:"config_cache"`
		MaxBufferMB int64  `mapstructure:"max_buffer_mb"`
	} `mapstructure:"local"`

	Server struct {
		Listen      string `mapstructure:"listen"`
		OIDCIssuer  string `mapstructure:"oidc_issuer"`
		OIDCClient  string `mapstructure:"oidc_client_id"`
		OIDCSecret  string `mapstructure:"oidc_client_secret_env"`
		RedirectURL string `mapstructure:"oidc_redirect_url"`
		SessionKey  string `mapstructure:"session_key_env"`
	} `mapstructure:"server"`

	Metrics struct {
		Listen string `mapstructure:"listen"`
	} `mapstructure:"metrics"`
}

// LoadLocal reads the YAML file at path, then overlays BMCGRAB_* env vars.
func LoadLocal(path string) (*Local, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("BMCGRAB")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("cyberark.cache_ttl", "1h")
	v.SetDefault("local.buffer_dir", "/var/lib/bmcgrab/buffer")
	v.SetDefault("local.config_cache", "/var/lib/bmcgrab/config.json")
	v.SetDefault("local.max_buffer_mb", 2048)
	v.SetDefault("server.listen", ":8080")
	v.SetDefault("metrics.listen", ":9090")
	v.SetDefault("database.password_env", "BMCGRAB_DB_PASSWORD")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Local
	if err := v.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// DatabaseDSN returns the DSN with the password injected from the environment
// when the DSN itself carries none.
func (c *Local) DatabaseDSN() string {
	dsn := c.Database.DSN
	if pw := os.Getenv(c.Database.PasswordEnv); pw != "" && !strings.Contains(dsn, "password=") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "password=" + pw
	}
	return dsn
}

// Validate checks the fields a collector cannot run without.
func (c *Local) Validate(mode string) error {
	var missing []string
	if c.Database.DSN == "" {
		missing = append(missing, "database.dsn")
	}
	if mode == "collector" && c.Region == "" {
		missing = append(missing, "region")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}
	return nil
}
