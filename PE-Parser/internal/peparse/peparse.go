package peparse

import (
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"PE-Parser/internal/stringsifter"
)

type Options struct {
	DumpHex     bool
	MaxDump     int
	ShowStrings bool
	MinStrLen   int

	UseSifter   bool
	RankLimit   int
	RankMin     float64
	AutoInstall bool
	AssumeYes   bool

	Quiet bool
}

type RankedString struct {
	Text  string
	Score *float64
}

type SectionReport struct {
	Index          int
	Name           string
	PtrRaw         uint32
	SizeRaw        uint32
	VirtualSize    uint32
	VirtualAddress uint32
	HexDump        string
	Truncated      bool

	Strings  []string
	Ranked   []RankedString
	RankNote string
}

type HeaderReport struct {
	Is64           bool
	ImageBaseVA    uint64
	SizeOfImage    uint64
	EntryPointRVA  uint32
	EntryPointVA   uint64
	OptionalFlavor string
}

type ImportDLL struct {
	Name      string
	Functions []string
}
type ImportReport struct {
	DLLs []ImportDLL
	Note string
}

type ExportSymbol struct {
	Name    string
	Ordinal uint16
	RVA     uint32
}
type ExportReport struct {
	DLLName string
	Symbols []ExportSymbol
	Note    string
}

type ResourceTypeSummary struct {
	TypeID   uint32
	TypeName string
	Count    int
}
type ResourceReport struct {
	Types []ResourceTypeSummary
	Note  string
}

type Report struct {
	Header    HeaderReport
	Sections  []SectionReport
	Imports   ImportReport
	Exports   ExportReport
	Resources ResourceReport

	GeneratedAt time.Time
	InputBase   string
}

func (r *Report) PrintConsole() {
	fmt.Printf("[+] PE: %s\n", r.InputBase)
	if r.Header.Is64 {
		fmt.Printf("    Format: %s  ImageBase: 0x%016X  SizeOfImage: 0x%X  EP RVA: 0x%08X  EP VA: 0x%016X\n",
			r.Header.OptionalFlavor, r.Header.ImageBaseVA, r.Header.SizeOfImage, r.Header.EntryPointRVA, r.Header.EntryPointVA)
	} else {
		fmt.Printf("    Format: %s  ImageBase: 0x%08X  SizeOfImage: 0x%X  EP RVA: 0x%08X  EP VA: 0x%08X\n",
			r.Header.OptionalFlavor, uint32(r.Header.ImageBaseVA), r.Header.SizeOfImage, r.Header.EntryPointRVA, uint32(r.Header.EntryPointVA))
	}

	fmt.Printf("\nFound %d sections:\n", len(r.Sections))
	for _, s := range r.Sections {
		fmt.Printf("#%.2X %-8s PtrRaw:0x%08X SizeRaw:0x%08X VSize:0x%08X RVA:0x%08X\n",
			s.Index, s.Name, s.PtrRaw, s.SizeRaw, s.VirtualSize, s.VirtualAddress)
	}

	if len(r.Imports.DLLs) > 0 {
		fmt.Printf("\nImports (%d DLLs):\n", len(r.Imports.DLLs))
		for _, d := range r.Imports.DLLs {
			fmt.Printf("  %s  (%d funcs)\n", d.Name, len(d.Functions))
		}
		if r.Imports.Note != "" {
			fmt.Println("  Note:", r.Imports.Note)
		}
	}

	if len(r.Exports.Symbols) > 0 || r.Exports.Note != "" {
		fmt.Printf("\nExports from %s: %d symbols\n", r.Exports.DLLName, len(r.Exports.Symbols))
		if r.Exports.Note != "" {
			fmt.Println("  Note:", r.Exports.Note)
		}
	}

	if len(r.Resources.Types) > 0 || r.Resources.Note != "" {
		fmt.Printf("\nResources: %d types\n", len(r.Resources.Types))
		for _, t := range r.Resources.Types {
			fmt.Printf("  %s (%d)\n", t.TypeName, t.Count)
		}
		if r.Resources.Note != "" {
			fmt.Println("  Note:", r.Resources.Note)
		}
	}
}

func Parse(path string, opts Options) (*Report, error) {
	abs := path
	if v, err := filepath.Abs(path); err == nil {
		abs = v
	}
	inputBase := filepath.Base(abs)

	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	f, err := pe.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("open pe: %w", err)
	}
	defer f.Close()

	r := &Report{GeneratedAt: time.Now(), InputBase: inputBase}

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		r.Header = HeaderReport{
			Is64:           false,
			ImageBaseVA:    uint64(oh.ImageBase),
			SizeOfImage:    uint64(oh.SizeOfImage),
			EntryPointRVA:  oh.AddressOfEntryPoint,
			EntryPointVA:   uint64(oh.ImageBase) + uint64(oh.AddressOfEntryPoint),
			OptionalFlavor: "PE32",
		}
	case *pe.OptionalHeader64:
		r.Header = HeaderReport{
			Is64:           true,
			ImageBaseVA:    oh.ImageBase,
			SizeOfImage:    uint64(oh.SizeOfImage),
			EntryPointRVA:  oh.AddressOfEntryPoint,
			EntryPointVA:   oh.ImageBase + uint64(oh.AddressOfEntryPoint),
			OptionalFlavor: "PE32+",
		}
	default:
		r.Header.OptionalFlavor = "Unknown"
	}

	secs := make([]SectionReport, 0, len(f.Sections))
	for i, s := range f.Sections {
		name := strings.TrimRight(s.Name, "\x00")
		sec := SectionReport{
			Index:          i,
			Name:           name,
			PtrRaw:         s.Offset,
			SizeRaw:        s.Size,
			VirtualSize:    s.VirtualSize,
			VirtualAddress: s.VirtualAddress,
		}

		if opts.DumpHex {
			b, _ := s.Data()
			limit := len(b)
			if opts.MaxDump > 0 && opts.MaxDump < limit {
				limit = opts.MaxDump
				sec.Truncated = true
			}
			if limit > 0 {
				sec.HexDump = hexDumpWithOffsets(s.Offset, b[:limit])
			}
		}

		if opts.ShowStrings {
			if b, err := s.Data(); err == nil {
				sec.Strings = extractStrings(b, opts.MinStrLen)
			}
		}

		secs = append(secs, sec)
	}
	r.Sections = secs

	if opts.UseSifter {
		_, sifterNote := stringsifter.EnsureAvailable(opts.AutoInstall, opts.AssumeYes, !opts.Quiet)

		for i := range r.Sections {
			plain := r.Sections[i].Strings
			if len(plain) == 0 {
				continue
			}

			scored, note := stringsifter.Rank(plain, opts.RankLimit, opts.RankMin)

			r.Sections[i].Ranked = toRanked(scored)

			r.Sections[i].Ranked = sortFilterRanked(r.Sections[i].Ranked, opts.RankLimit, opts.RankMin)
			if r.Sections[i].RankNote == "" && note != "" {
				r.Sections[i].RankNote = note
			}
			if r.Sections[i].RankNote == "" && sifterNote != "" {
				r.Sections[i].RankNote = sifterNote
			}
		}
	}

	r.Imports = parseImports(f, data, r.Header.Is64)
	r.Exports = parseExports(f, data)
	r.Resources = parseResources(f, data)

	return r, nil
}

func toRanked(in []stringsifter.ScoredString) []RankedString {
	out := make([]RankedString, 0, len(in))
	for _, s := range in {
		if s.ScorePtr != nil {
			v := *s.ScorePtr
			out = append(out, RankedString{Text: s.Text, Score: &v})
		} else {
			out = append(out, RankedString{Text: s.Text, Score: nil})
		}
	}
	return out
}

func sortFilterRanked(in []RankedString, limit int, minScore float64) []RankedString {
	filtered := in[:0]
	for _, r := range in {
		if r.Score == nil {
			if minScore <= 0 {
				filtered = append(filtered, r)
			}
			continue
		}
		if *r.Score >= minScore {
			filtered = append(filtered, r)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		li, lj := filtered[i].Score, filtered[j].Score
		if li == nil && lj == nil {
			return false
		}
		if li == nil {
			return false
		}
		if lj == nil {
			return true
		}
		return *li > *lj
	})
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	out := make([]RankedString, len(filtered))
	copy(out, filtered)
	return out
}
