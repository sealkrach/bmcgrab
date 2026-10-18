// Package fakeccp is a stand-in for the CyberArk Central Credential Provider
// (AIMWebService) for tests and labs: HTTPS with mandatory client
// certificates, GET /AIMWebService/api/Accounts?AppID=&Safe=&Object=, JSON
// answer with Content/UserName, CCP-style error bodies. Certificates are
// generated on the fly and written to disk so the real client code (file
// loading, mTLS) is exercised.
package fakeccp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Path is the endpoint path of the real CCP.
const Path = "/AIMWebService/api/Accounts"

type account struct{ user, pass string }

// Server is a running fake CCP.
type Server struct {
	URL            string // full endpoint URL, ready for cyberark.url
	CAFile         string // CA that signed the server certificate (cyberark.ca_file)
	ClientCertFile string // client certificate allowed by the server
	ClientKeyFile  string

	appID string
	srv   *httptest.Server

	mu       sync.Mutex
	accounts map[string]account
	calls    map[string]int
	total    atomic.Int64
	status   atomic.Int32 // forced HTTP status for every request (0 = off)
	delayNs  atomic.Int64
}

// New starts the server; files are written to dir. appID is the only AppID it accepts.
func New(dir, appID string) (*Server, error) {
	ca, caKey, caPEM, err := newCA()
	if err != nil {
		return nil, err
	}
	srvCert, err := issue(ca, caKey, "fakeccp", false)
	if err != nil {
		return nil, err
	}
	cliCertPEM, cliKeyPEM, err := issuePEM(ca, caKey, "bmcgrab-collector", true)
	if err != nil {
		return nil, err
	}
	s := &Server{appID: appID, accounts: map[string]account{}, calls: map[string]int{}}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{srvCert},
		ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
	}
	s.srv.StartTLS()
	s.URL = s.srv.URL + Path
	s.CAFile = filepath.Join(dir, "ca.pem")
	s.ClientCertFile = filepath.Join(dir, "client.crt")
	s.ClientKeyFile = filepath.Join(dir, "client.key")
	for p, b := range map[string][]byte{s.CAFile: caPEM, s.ClientCertFile: cliCertPEM, s.ClientKeyFile: cliKeyPEM} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			s.srv.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Server) Close() { s.srv.Close() }

// Set creates or rotates an account.
func (s *Server) Set(safe, object, user, pass string) {
	s.mu.Lock()
	s.accounts[safe+"/"+object] = account{user, pass}
	s.mu.Unlock()
}

// Delete removes an account (the CCP then answers 404).
func (s *Server) Delete(safe, object string) {
	s.mu.Lock()
	delete(s.accounts, safe+"/"+object)
	s.mu.Unlock()
}

// Calls is the number of successful or failed lookups of one account.
func (s *Server) Calls(safe, object string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[safe+"/"+object]
}

// TotalCalls counts every request that reached the handler.
func (s *Server) TotalCalls() int { return int(s.total.Load()) }

// ForceStatus makes every request answer with this HTTP status (0 = normal).
func (s *Server) ForceStatus(code int) { s.status.Store(int32(code)) }

// SetDelay adds latency to every request.
func (s *Server) SetDelay(d time.Duration) { s.delayNs.Store(int64(d)) }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.total.Add(1)
	if d := s.delayNs.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	if r.URL.Path != Path || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	key := q.Get("Safe") + "/" + q.Get("Object")
	s.mu.Lock()
	s.calls[key]++
	a, ok := s.accounts[key]
	s.mu.Unlock()

	if code := int(s.status.Load()); code != 0 {
		ccpError(w, code, "APPAP999E", "forced failure for tests")
		return
	}
	if q.Get("AppID") != s.appID {
		ccpError(w, http.StatusForbidden, "APPAP008E", "Application "+q.Get("AppID")+" is not authorized (secret-looking text that must never be logged)")
		return
	}
	if !ok {
		ccpError(w, http.StatusNotFound, "APPAP004E", "Password object matching query [Safe="+q.Get("Safe")+";Object="+q.Get("Object")+"] was not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"Content": a.pass, "UserName": a.user, "Address": "", "Safe": q.Get("Safe"), "Name": q.Get("Object"),
		"PolicyID": "BMC", "DeviceType": "Operating System", "CPMDisabled": nil,
	})
}

func ccpError(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"ErrorCode": errCode, "ErrorMsg": msg})
}

// ------------------------------------------------------------- certificates

func newCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fakeccp test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func leaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, client bool) (der []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if client {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.DNSNames = []string{"localhost"}
		tpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}
	der, err = x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	return der, key, err
}

func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, client bool) (tls.Certificate, error) {
	der, key, err := leaf(ca, caKey, cn, client)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func issuePEM(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, client bool) (certPEM, keyPEM []byte, err error) {
	der, key, err := leaf(ca, caKey, cn, client)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}
