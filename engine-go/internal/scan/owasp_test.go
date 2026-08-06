package scan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A deliberately leaky test server: a real SQLi, a correctly-safe endpoint, and
// a benign reflector that must NOT be flagged. This is how we prove the active
// checks fire on the vulnerable case and stay silent on the safe one.
func vulnServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(500)
			w.Write([]byte(`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near "'" at line 1`))
			return
		}
		w.Write([]byte(`{"id":1,"name":"alice"}`))
	})
	mux.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "{{7*13}}" {
			name = "91"
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>Hello " + name + "</p>"))
	})
	// A safe endpoint: it reflects but HTML-encodes, so XSS must not fire.
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		q = strings.ReplaceAll(q, "<", "&lt;")
		q = strings.ReplaceAll(q, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>Results for " + q + "</p>"))
	})
	return httptest.NewServer(mux)
}

func TestActiveChecks(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()
	c := newClient(5*time.Second, nil)

	t.Run("sqli fires with evidence", func(t *testing.T) {
		base := c.capture("GET", srv.URL+"/user?id=1", "baseline", nil)
		f := c.checkSQLi(srv.URL+"/user?id=1", "id", base)
		if f == nil {
			t.Fatal("SQLi not detected on the vulnerable endpoint")
		}
		if f.Confidence != "high" || f.Evidence == nil || len(f.Evidence.Exchanges) < 2 {
			t.Errorf("finding lacks the evidence that makes it confirmable: %+v", f)
		}
		if f.Evidence.Reproduced < 2 {
			t.Errorf("reproduced only %d times", f.Evidence.Reproduced)
		}
	})

	t.Run("ssti fires on evaluation", func(t *testing.T) {
		base := c.capture("GET", srv.URL+"/render?name=x", "baseline", nil)
		if f := c.checkSSTI(srv.URL+"/render?name=x", "name", base); f == nil {
			t.Fatal("SSTI not detected when {{7*13}} evaluated to 91")
		}
	})

	t.Run("no false positive on the safe reflector", func(t *testing.T) {
		base := c.capture("GET", srv.URL+"/safe?q=x", "baseline", nil)
		if f := c.checkXSS(srv.URL+"/safe?q=x", "q", base); f != nil {
			t.Errorf("XSS falsely fired on an endpoint that HTML-encodes: %+v", f)
		}
		if f := c.checkSQLi(srv.URL+"/safe?q=x", "q", base); f != nil {
			t.Errorf("SQLi falsely fired on a safe endpoint: %+v", f)
		}
	})
}
