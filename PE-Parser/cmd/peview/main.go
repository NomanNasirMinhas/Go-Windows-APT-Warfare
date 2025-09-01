package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"PE-Parser/internal/peparse"
	"PE-Parser/internal/reporthtml"
)

func main() {
	pePath := flag.String("file", "", "Path to the PE file")

	dumpHex := flag.Bool("dump", true, "Hex-dump section data (applies to console and HTML)")
	maxDump := flag.Int("maxdump", 1024, "Max bytes to hex-dump per section (0 = no limit)")
	showStrings := flag.Bool("strings", true, "Extract printable strings from section data (applies to console and HTML)")
	minStrLen := flag.Int("minstrlen", 4, "Minimum printable string length")

	useSifter := flag.Bool("rank", false, "Rank strings with StringSifter (rank_strings)")
	rankLimit := flag.Int("ranklimit", 25, "Top-N ranked strings per section (0 = all)")
	rankMin := flag.Float64("rankmin", 0.0, "Minimum StringSifter score to include")
	autoInstall := flag.Bool("install", false, "If rank_strings is missing, offer to install StringSifter")
	assumeYes := flag.Bool("y", false, "Assume yes to install prompt (non-interactive)")

	writeHTML := flag.Bool("html", true, "Write an HTML report next to the target file and suppress console output")

	flag.Parse()

	if *pePath == "" {
		fmt.Fprintln(os.Stderr, "Usage: peview -file <path-to-pe-file> [flags]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	opts := peparse.Options{
		DumpHex:     *dumpHex,
		MaxDump:     *maxDump,
		ShowStrings: *showStrings,
		MinStrLen:   *minStrLen,
		UseSifter:   *useSifter,
		RankLimit:   *rankLimit,
		RankMin:     *rankMin,
		AutoInstall: *autoInstall,
		AssumeYes:   *assumeYes,
		Quiet:       *writeHTML,
	}

	report, err := peparse.Parse(*pePath, opts)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	if *writeHTML {
		out := htmlOutPath(*pePath)
		if err := reporthtml.WriteHTML(out, *pePath, report, reporthtml.Params{
			UseSifter: opts.UseSifter,
			RankLimit: opts.RankLimit,
			RankMin:   opts.RankMin,
		}); err != nil {
			log.Fatalf("HTML write error: %v", err)
		}
		return
	}
	report.PrintConsole()
}

func htmlOutPath(target string) string {
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	return filepath.Join(dir, base+".peview.html")
}
