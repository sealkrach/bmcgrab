package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// auth implements the OIDC authorization-code flow with an in-memory session
// store. When no issuer is configured the server runs open (lab only) and
// every action is attributed to "anonymous".
type auth struct {
	enabled  bool
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config

	mu       sync.Mutex
	states   map[string]time.Time
	sessions map[string]session
}

type session struct {
	user    string
	expires time.Time
}

type ctxKey struct{}

func newAuth(ctx context.Context, issuer, clientID, secretEnv, redirect string) (*auth, error) {
	a := &auth{states: map[string]time.Time{}, sessions: map[string]session{}}
	if issuer == "" {
		return a, nil
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	a.enabled = true
	a.provider = p
	a.verifier = p.Verifier(&oidc.Config{ClientID: clientID})
	a.oauth = oauth2.Config{
		ClientID: clientID, ClientSecret: os.Getenv(secretEnv), Endpoint: p.Endpoint(),
		RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return a, nil
}

// user returns the authenticated user name from the request context.
func user(r *http.Request) string {
	if u, ok := r.Context().Value(ctxKey{}).(string); ok && u != "" {
		return u
	}
	return "anonymous"
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *auth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, "anonymous")))
			return
		}
		c, err := r.Cookie("bmcgrab_session")
		if err == nil {
			a.mu.Lock()
			s, ok := a.sessions[hashKey(c.Value)]
			a.mu.Unlock()
			if ok && time.Now().Before(s.expires) {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s.user)))
				return
			}
		}
		state := randToken()
		a.mu.Lock()
		a.states[state] = time.Now().Add(10 * time.Minute)
		a.mu.Unlock()
		http.Redirect(w, r, a.oauth.AuthCodeURL(state), http.StatusFound)
	})
}

func (a *auth) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	a.mu.Lock()
	exp, ok := a.states[state]
	delete(a.states, state)
	a.mu.Unlock()
	if !ok || time.Now().After(exp) {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	tok, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"preferred_username"`
		Sub   string `json:"sub"`
	}
	_ = idt.Claims(&claims)
	who := claims.Email
	if who == "" {
		who = claims.Name
	}
	if who == "" {
		who = claims.Sub
	}
	sid := randToken()
	a.mu.Lock()
	a.sessions[hashKey(sid)] = session{user: who, expires: time.Now().Add(8 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "bmcgrab_session", Value: sid, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *auth) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("bmcgrab_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, hashKey(c.Value))
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "bmcgrab_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
