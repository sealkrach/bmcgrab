package server

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/sealkrach/bmcgrab/internal/config"
)

// TestTemplatesRender executes every page template with representative data
// so a broken template fails CI rather than a request.
func TestTemplatesRender(t *testing.T) {
	funcs := template.FuncMap{
		"ago": ago, "dur": func(d time.Duration) string { return d.String() },
		"json":   func(v any) template.JS { return "" },
		"title":  strings.Title, //nolint:staticcheck
		"fmtDur": func(d time.Duration) string { return d.String() },
		"list":   func(s ...string) []string { return s },
	}
	tpl, err := template.New("").Funcs(funcs).ParseFS(uiFS, "ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]any{
		"dashboard.html":    overview{},
		"servers.html":      map[string]any{"Rows": nil, "Regions": nil, "Region": "", "Status": "", "Q": ""},
		"config.html":       map[string]any{"Cfg": config.Default(), "History": nil, "Enabled": ""},
		"check.html":        nil,
		"check_result.html": nil,
		"audit.html":        nil,
	}
	for name, data := range cases {
		var b bytes.Buffer
		if err := tpl.ExecuteTemplate(&b, name, page{Title: name, Data: data}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
