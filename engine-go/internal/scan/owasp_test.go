package scan

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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
		// Realistic error-based SQLi: an ODD number of quotes breaks the query
		// and errors; a balanced pair escapes to a literal and recovers. This is
		// what lets the differential control confirm a real injection instead of
		// rejecting a naive "errors on any quote" faker.
		if strings.Count(id, "'")%2 == 1 {
			w.WriteHeader(500)
			w.Write([]byte(`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near "'" at line 1`))
			return
		}
		w.Write([]byte(`{"id":1,"name":"alice"}`))
	})
	// A safe endpoint that always errors on odd input — the differential must
	// reject it as "errors on everything", not report SQLi.
	mux.HandleFunc("/always500", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if v != "" && !isAllDigits(v) {
			w.WriteHeader(500)
			w.Write([]byte(`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version`))
			return
		}
		w.Write([]byte(`{"id":1}`))
	})
	mux.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		// Evaluate any {{a*b}}, so both {{7*13}} and the {{6*6}} confirm probe work.
		name := evalMul(r.URL.Query().Get("name"))
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>Hello " + name + "</p>"))
	})
	// A page that always contains "91" but never evaluates — the second-product
	// differential must reject it.
	mux.HandleFunc("/fake91", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>Order 91 for " + r.URL.Query().Get("name") + "</p>"))
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

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// evalMul turns "{{a*b}}" into the product, leaving anything else untouched —
// a minimal but genuine template evaluator for the test fixture.
func evalMul(s string) string {
	if !strings.HasPrefix(s, "{{") || !strings.HasSuffix(s, "}}") {
		return s
	}
	inner := strings.TrimSpace(s[2 : len(s)-2])
	parts := strings.SplitN(inner, "*", 2)
	if len(parts) != 2 {
		return s
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return s
	}
	return strconv.Itoa(a * b)
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

	// The differential controls must reject the false-positive traps.
	t.Run("sqli differential rejects errors-on-everything", func(t *testing.T) {
		base := c.capture("GET", srv.URL+"/always500?id=1", "baseline", nil)
		if f := c.checkSQLi(srv.URL+"/always500?id=1", "id", base); f != nil {
			t.Errorf("SQLi falsely fired where the balanced-quote control also errors: %+v", f)
		}
	})
	t.Run("ssti differential rejects a coincidental 91", func(t *testing.T) {
		base := c.capture("GET", srv.URL+"/fake91?name=x", "baseline", nil)
		if f := c.checkSSTI(srv.URL+"/fake91?name=x", "name", base); f != nil {
			t.Errorf("SSTI falsely fired where {{6*6}} does not evaluate to 36: %+v", f)
		}
	})
}
