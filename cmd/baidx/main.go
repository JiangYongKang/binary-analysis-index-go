// Command baidx is a small CLI for the local binary analysis index:
// it scans files under a rule-set version and can show stored records.
//
// Usage:
//
//	baidx [-index FILE] scan [-rules VERSION] FILE...
//	baidx [-index FILE] list
//	baidx [-index FILE] get -sample HASH [-rules VERSION]
//	baidx versions
//
// It uses only local files and the built-in rule sets; no network, scanner
// binary or credentials are involved.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
	"github.com/highcumontoa/binary-analysis-index-go/internal/index"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
	"github.com/highcumontoa/binary-analysis-index-go/internal/scan"
)

const usageText = `baidx - local binary sample analysis index

Commands:
  scan [-rules VERSION] FILE...  analyse files under a rule-set version
  list                           list stored records
  get -sample HASH [-rules V]    show one record (or all versions of a sample)
  versions                       list registered rule-set versions
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}

	// Pre-parse the global -index flag so it may appear before or after the
	// subcommand; everything else is passed to the subcommand's flag set.
	indexPath := ".baidx/index.json"
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-index" || a == "--index":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "-index requires a value")
				return 2
			}
			indexPath = args[i+1]
			i++
		case strings.HasPrefix(a, "-index="):
			indexPath = strings.TrimPrefix(a, "-index=")
		case strings.HasPrefix(a, "--index="):
			indexPath = strings.TrimPrefix(a, "--index=")
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	cmd, rest := positional[0], positional[1:]

	reg := rules.NewRegistry()
	reg.MustRegister(rules.BuiltinV1())
	reg.MustRegister(rules.BuiltinV2())

	switch cmd {
	case "versions":
		for _, v := range reg.Versions() {
			fmt.Fprintln(stdout, v)
		}
		return 0
	case "scan", "list", "get":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", cmd, usageText)
		return 2
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	ruleVersion := fs.String("rules", rules.VersionV2, "rule-set version")
	sampleHash := fs.String("sample", "", "sample content hash")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	store := index.NewFileStore(indexPath)

	switch cmd {
	case "list":
		return cmdList(store, stdout, stderr)
	case "get":
		return cmdGet(store, *sampleHash, *ruleVersion, stdout, stderr)
	case "scan":
		return cmdScan(reg, store, *ruleVersion, fs.Args(), stdout, stderr)
	}
	return 2
}

func openIndex(store index.Store, analyzer index.AnalyzerFunc) (*index.Index, error) {
	return index.New(analyzer, index.WithStore(store))
}

func cmdScan(reg *rules.Registry, store index.Store, version string, files []string, stdout, stderr io.Writer) int {
	if len(files) == 0 {
		fmt.Fprintln(stderr, "scan requires at least one FILE")
		return 2
	}
	if _, err := reg.Get(version); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	az := analysis.NewAnalyzer(reg)
	svc := scan.New(az, nil)
	idx, err := openIndex(store, svc.AnalyzerFunc())
	if err != nil {
		fmt.Fprintf(stderr, "open index: %v\n", err)
		return 1
	}
	svc = scan.New(az, idx)

	exit := 0
	for _, file := range files {
		rec, err := svc.ScanFile(context.Background(), file, version)
		if err != nil {
			fmt.Fprintf(stderr, "scan %s: %v\n", file, err)
			exit = 1
			continue
		}
		printRecord(stdout, rec)
	}
	return exit
}

func cmdList(store index.Store, stdout, stderr io.Writer) int {
	snap, err := store.Load()
	if err != nil {
		fmt.Fprintf(stderr, "load index: %v\n", err)
		return 1
	}
	if len(snap.Records) == 0 {
		fmt.Fprintln(stdout, "(empty index)")
		return 0
	}
	for _, r := range snap.Records {
		printRecord(stdout, r)
	}
	return 0
}

func cmdGet(store index.Store, sampleHash, version string, stdout, stderr io.Writer) int {
	if sampleHash == "" {
		fmt.Fprintln(stderr, "get requires -sample")
		return 2
	}
	snap, err := store.Load()
	if err != nil {
		fmt.Fprintf(stderr, "load index: %v\n", err)
		return 1
	}
	found := false
	for _, r := range snap.Records {
		if r.SampleID != sampleHash {
			continue
		}
		if version != "" && r.Version != version {
			continue
		}
		printRecord(stdout, r)
		found = true
	}
	if !found {
		fmt.Fprintln(stderr, "no matching record")
		return 1
	}
	return 0
}

func printRecord(w io.Writer, r *index.Record) {
	if r.Status == index.StatusFailed {
		e := r.Error
		fmt.Fprintf(w, "sample=%s file=%s rules=%s status=failed kind=%s offset=%d rule=%s detail=%q\n",
			r.SampleID, r.Filename, r.Version, e.Kind, e.Offset, e.RuleID, e.Message)
		return
	}
	var hits []string
	for _, m := range r.Matches {
		hits = append(hits, m.RuleID+":"+m.Severity)
	}
	fmt.Fprintf(w, "sample=%s file=%s format=%s/%s rules=%s status=%s verdict=%s matches=%v basis=%q\n",
		r.SampleID, r.Filename, r.Format, r.Class, r.Version, r.Status, r.Verdict, hits, r.Basis)
}
