// Command smarthunt is the Go reconnaissance and bug-hunting engine.
//
//	smarthunt example.com                 # deep scan one host
//	smarthunt '*.example.com'             # wildcard: enumerate, then go deep
//	smarthunt example.com --wildcard      # force wildcard mode
//	smarthunt example.com --threads 100 --out results/
//	smarthunt --tools                     # list detected external tools
//
// It works with zero external tools — every stage has a pure-Go fallback — and
// gets deeper with each recon tool it finds installed.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Amansinghtomar12/SmartHunt/engine-go/internal/scan"
)

func main() {
	var (
		wildcard = flag.Bool("wildcard", false, "force wildcard mode (enumerate subdomains)")
		threads  = flag.Int("threads", 50, "concurrent workers")
		timeout  = flag.Int("timeout", 12, "per-request timeout, seconds")
		maxPages = flag.Int("max-pages", 400, "crawl page cap")
		maxJS    = flag.Int("max-js", 300, "JavaScript file cap")
		out      = flag.String("out", "smarthunt-results", "output directory")
		cookie   = flag.String("cookie", "", "Cookie header for authenticated testing")
		bearer   = flag.String("bearer", "", "Bearer token for authenticated testing")
		listTool = flag.Bool("tools", false, "list detected external tools and exit")
		yes      = flag.Bool("y", false, "skip the authorization prompt")
	)
	flag.Parse()

	if *listTool {
		scan.PrintTools()
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: smarthunt <domain|*.domain> [flags]  (--tools to list tools)")
		os.Exit(2)
	}
	target := args[0]
	isWildcard := *wildcard || strings.HasPrefix(target, "*.") || strings.HasPrefix(target, ".")

	scope := target
	if isWildcard {
		scope = "*." + scan.Normalize(target)
	}
	if !*yes {
		fmt.Printf("\nTarget scope : %s\nMode         : %s\n", scope, modeName(isWildcard))
		fmt.Println("\nThis sends live traffic to the target. Only continue if you own it")
		fmt.Println("or have written authorization to test it.")
		fmt.Print("\nConfirm you are authorized [y/N]: ")
		var reply string
		fmt.Scanln(&reply)
		if r := strings.ToLower(strings.TrimSpace(reply)); r != "y" && r != "yes" {
			fmt.Println("aborted")
			return
		}
	}

	headers := map[string]string{}
	if *cookie != "" {
		headers["Cookie"] = *cookie
	}
	if *bearer != "" {
		headers["Authorization"] = "Bearer " + strings.TrimPrefix(*bearer, "Bearer ")
	}

	cfg := &scan.Config{
		Target: target, Wildcard: isWildcard, Threads: *threads,
		Timeout:  time.Duration(*timeout) * time.Second,
		MaxPages: *maxPages, MaxJSFiles: *maxJS, AuthHeader: headers,
	}

	eng := scan.New(cfg, func(level, msg string) {
		prefix := map[string]string{
			"stage": "\033[36m", "found": "\033[35m", "warn": "\033[33m", "error": "\033[31m",
		}[level]
		fmt.Printf("%s%s\033[0m\n", prefix, msg)
	})
	res := eng.Run()

	// Print the one triaged finding — the headline.
	fmt.Println("\n" + strings.Repeat("─", 68))
	fmt.Print(res.Report.Markdown)
	fmt.Println(strings.Repeat("─", 68))

	written, err := scan.Export(res, *out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "export failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nWrote %d file(s):\n", len(written))
	for _, p := range written {
		fmt.Println("  " + p)
	}
}

func modeName(w bool) string {
	if w {
		return "wildcard"
	}
	return "domain"
}
