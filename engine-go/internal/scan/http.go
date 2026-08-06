package scan

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a shared HTTP client tuned for scanning: connection reuse, a bounded
// timeout, no automatic redirect following (a redirect is often the finding),
// and TLS verification off because bug-bounty targets routinely have imperfect
// certificates and refusing them would just blind the scan.
type Client struct {
	hc      *http.Client
	headers map[string]string // e.g. an authenticated session
}

func newClient(timeout time.Duration, headers map[string]string) *Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}
	return &Client{
		hc: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			// Never follow redirects automatically.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		headers: headers,
	}
}

// capture performs one request and records exactly what crossed the wire.
// It never returns an error — a failed request is a recorded Exchange with Err
// set, because "the server refused" is itself evidence.
func (c *Client) capture(method, rawURL, note string, extra map[string]string) Exchange {
	x := Exchange{Method: strings.ToUpper(method), URL: rawURL, Note: note,
		ReqHeaders: map[string]string{}}
	req, err := http.NewRequest(x.Method, rawURL, nil)
	if err != nil {
		x.Err = err.Error()
		return x
	}
	req.Header.Set("User-Agent", "SmartHunt/2.0 (+recon)")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	for k := range req.Header {
		x.ReqHeaders[k] = req.Header.Get(k)
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	x.ElapsedMs = time.Since(start).Milliseconds()
	if err != nil {
		x.Err = err.Error()
		return x
	}
	defer resp.Body.Close()
	x.Status = resp.StatusCode
	x.RespHeaders = map[string]string{}
	for k := range resp.Header {
		x.RespHeaders[k] = resp.Header.Get(k)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody*3))
	x.RespBody = string(body)
	if resp.Request != nil && resp.Request.URL != nil {
		x.URL = resp.Request.URL.String()
	}
	return x
}

// verifyRepeat re-runs an exchange and counts how many times pred still holds.
// A one-off response is not evidence; the evidence rule requires reproduction.
func (c *Client) verifyRepeat(x Exchange, pred func(Exchange) bool, attempts int) int {
	n := 0
	for i := 0; i < attempts; i++ {
		r := c.capture(x.Method, x.URL, "reproduction attempt", nil)
		if pred(r) {
			n++
		}
	}
	return n
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isHTML(x Exchange) bool {
	ct := strings.ToLower(x.RespHeaders["Content-Type"])
	return strings.Contains(ct, "html") || strings.Contains(ct, "xml") || ct == ""
}
