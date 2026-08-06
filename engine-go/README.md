# SmartHunt — Go engine

A ground-up rewrite of the scan engine in Go. The reason is concurrency: a recon
scan is thousands of independent network round-trips, and goroutines express
that directly — the engine keeps hundreds of requests in flight at once, capped
by a worker pool, with none of the per-stage overhead the Python version paid.

This is the **engine core**, built to be correct first and complete over time.
It already does the full spine of a scan and gets the two things that matter
right by construction.

## What it does today

```bash
cd engine-go
go build -o smarthunt .

./smarthunt example.com                 # deep scan one host
./smarthunt '*.example.com'             # wildcard: enumerate, then go deep
./smarthunt example.com --threads 200   # concurrency scales with the pool
./smarthunt --tools                     # list detected external tools
```

Pipeline: subdomain enumeration (wildcard) → concurrent HTTP probe + tech
fingerprint → crawl + URL collection → JavaScript mining (endpoints + secrets,
deduplicated) → active OWASP checks (SQL injection across 5 engines, SSTI,
path traversal, reflected XSS) → exposed-file checks (`.env`, `.git`) → triage.

Every active check **captures the request and response that prove it** and
reproduces the behaviour before reporting. On the bundled test target it runs
the whole pipeline in about a second.

## The two things it gets right

**No false-positive criticals.** A finding is only ever shown at its real
severity if this engine captured first-hand evidence of the behaviour. A version
banner matched to a CVE, a secret string that may be a placeholder, an external
tool's say-so we never reproduced — all of it is a **lead**, shown as `info`,
never counted as critical/high. This is enforced in one place (`classifyConfidence`
in `triage.go`) for the list, the headline counts, and the exports alike, so the
"every critical was a false positive" failure cannot recur.

**One proven finding, or an honest nothing.** Triage applies the evidence gate
to the whole set and emits exactly one reportable finding — with raw
request/response proof, `curl` steps, and a severity graded from what was
*demonstrated*, not from the bug class's reputation — or says there isn't one.

## Tools it drives

The engine works with **zero external tools** — every stage has a pure-Go
fallback. It also detects and uses 42 well-known recon tools when installed
(`subfinder`, `httpx`, `nuclei`, `katana`, `gau`, `dnsx`, `trufflehog`,
`ffuf`, and more — see `./smarthunt --tools`), because coverage in recon comes
from running many sources and merging.

## Not ported yet

Being honest about scope — these still live in the Python tool and are on the
list: the two-account IDOR proof, the CVE-inference stage, content discovery and
parameter fuzzing, nuclei/dalfox integration, screenshots, the exhaustive
convergence loop, the desktop and browser UIs, and the AI report writer. The
Python engine at the repository root remains the full-featured tool while this
one is built out; both apply the same evidence rule.

## Tests

```bash
go test ./...
```

Covers the confidence classifier (leads never shown as critical), the triage
gate (proven wins, leads dropped, nothing-when-only-leads), credential masking,
and the active checks firing on a planted-vulnerability server while staying
silent on a safe reflector.
