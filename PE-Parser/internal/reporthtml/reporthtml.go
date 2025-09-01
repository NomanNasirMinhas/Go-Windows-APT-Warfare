package reporthtml

import (
	"PE-Parser/internal/peparse"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Params struct {
	UseSifter bool
	RankLimit int
	RankMin   float64
}

func WriteHTML(outPath, inputPath string, r *peparse.Report, p Params) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().Format(time.RFC3339)
	title := fmt.Sprintf("PE Report — %s", filepath.Base(inputPath))

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	sb.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	sb.WriteString(`<title>` + html.EscapeString(title) + `</title>`)
	sb.WriteString(styles())
	sb.WriteString(`</head><body>`)

	sb.WriteString(`<header><h1>` + html.EscapeString(title) + `</h1>`)
	sb.WriteString(`<small>Generated ` + html.EscapeString(now) + ` — ` + html.EscapeString(inputPath) + `</small>`)
	sb.WriteString(`</header><main>`)

	sb.WriteString(`<section class="card"><h2>PE Optional Header</h2><div class="content"><div class="kv">`)
	sb.WriteString(`<div>Format</div><div>` + html.EscapeString(r.Header.OptionalFlavor) + `</div>`)
	if r.Header.Is64 {
		sb.WriteString(fmt.Sprintf(`<div>ImageBase</div><div>0x%016X</div>`, r.Header.ImageBaseVA))
		sb.WriteString(fmt.Sprintf(`<div>EntryPoint RVA</div><div>0x%08X</div>`, r.Header.EntryPointRVA))
		sb.WriteString(fmt.Sprintf(`<div>EntryPoint VA</div><div>0x%016X</div>`, r.Header.EntryPointVA))
	} else {
		sb.WriteString(fmt.Sprintf(`<div>ImageBase</div><div>0x%08X</div>`, uint32(r.Header.ImageBaseVA)))
		sb.WriteString(fmt.Sprintf(`<div>EntryPoint RVA</div><div>0x%08X</div>`, r.Header.EntryPointRVA))
		sb.WriteString(fmt.Sprintf(`<div>EntryPoint VA</div><div>0x%08X</div>`, uint32(r.Header.EntryPointVA)))
	}
	sb.WriteString(fmt.Sprintf(`<div>SizeOfImage</div><div>0x%X bytes</div>`, r.Header.SizeOfImage))
	sb.WriteString(`</div>`)
	println("String Sifter:", p.UseSifter, "limit:", p.RankLimit, "min:", p.RankMin)
	if p.UseSifter {
		sb.WriteString(`<p class="content"><span class="badge">StringSifter enabled</span> &nbsp; Ranked with <code>rank_strings</code> (top ` +
			html.EscapeString(fmt.Sprintf("%d", effLimit(p.RankLimit))) + `, min-score ` + html.EscapeString(fmt.Sprintf("%.3f", p.RankMin)) +
			`). See per-section details. </p>`)
	}
	sb.WriteString(`</section>`)

	sb.WriteString(`<section class="card"><h2>Contents</h2><div class="content toc"><ul>`)
	sb.WriteString(`<li><a href="#sec-summary">Sections Summary</a></li>`)
	sb.WriteString(`<li><a href="#imports">Imports</a></li>`)
	sb.WriteString(`<li><a href="#exports">Exports</a></li>`)
	sb.WriteString(`<li><a href="#resources">Resources</a></li>`)
	sb.WriteString(`</ul></div></section>`)

	sb.WriteString(`<section id="sec-summary" class="card"><h2>Sections Summary</h2><div class="content"><table><thead><tr>`)
	sb.WriteString(`<th>#</th><th>Name</th><th>PtrRaw</th><th>SizeRaw</th><th>VirtualSize</th><th>VirtualAddress (RVA)</th></tr></thead><tbody>`)
	for _, s := range r.Sections {
		sb.WriteString(fmt.Sprintf(
			`<tr><td><code>#%.2X</code></td><td id="sec-%02X"><code>%s</code></td><td><code>0x%08X</code></td><td><code>0x%08X</code></td><td><code>0x%08X</code></td><td><code>0x%08X</code></td></tr>`,
			s.Index, s.Index, html.EscapeString(s.Name), s.PtrRaw, s.SizeRaw, s.VirtualSize, s.VirtualAddress,
		))
	}
	sb.WriteString(`</tbody></table></div></section>`)

	for _, s := range r.Sections {
		sb.WriteString(`<section class="card">`)
		sb.WriteString(fmt.Sprintf(`<h3 id="sec-%02X"><code>#%.2X</code> %s</h3>`, s.Index, s.Index, html.EscapeString(s.Name)))
		sb.WriteString(`<div class="content">`)
		sb.WriteString(`<div class="kv">`)
		sb.WriteString(fmt.Sprintf(`<div>PtrRaw</div><div><code>0x%08X</code></div>`, s.PtrRaw))
		sb.WriteString(fmt.Sprintf(`<div>SizeRaw</div><div><code>0x%08X</code></div>`, s.SizeRaw))
		sb.WriteString(fmt.Sprintf(`<div>VirtualSize</div><div><code>0x%08X</code></div>`, s.VirtualSize))
		sb.WriteString(fmt.Sprintf(`<div>VirtualAddress (RVA)</div><div><code>0x%08X</code></div>`, s.VirtualAddress))
		sb.WriteString(`</div>`)

		sb.WriteString(`<div class="details"><details><summary>Hex dump</summary><div class="content">`)
		if s.HexDump == "" {
			sb.WriteString(`<p class="badge">No hex dump available</p>`)
		} else {
			if s.Truncated {
				sb.WriteString(`<p class="badge">Truncated to maxdump</p>`)
			}
			sb.WriteString(`<pre>`)
			sb.WriteString(html.EscapeString(s.HexDump))
			sb.WriteString(`</pre>`)
		}
		sb.WriteString(`</div></details></div>`)

		sb.WriteString(`<div class="details"><details><summary>Strings (plain)</summary><div class="content">`)
		if len(s.Strings) == 0 {
			sb.WriteString(`<p class="badge">No printable strings found</p>`)
		} else {
			sb.WriteString(`<pre>`)
			for _, line := range s.Strings {
				sb.WriteString(html.EscapeString(line))
				sb.WriteByte('\n')
			}
			sb.WriteString(`</pre>`)
		}
		sb.WriteString(`</div></details></div>`)

		// sb.WriteString(`<div class="details"><details open><summary>Ranked Strings (StringSifter)</summary><div class="content">`)
		// if s.RankNote != "" {
		// 	sb.WriteString(`<p class="note">` + html.EscapeString(s.RankNote) + `</p>`)
		// }
		// if len(s.Ranked) == 0 {
		// 	sb.WriteString(`<p class="badge">No ranked strings</p>`)
		// } else {
		// 	sb.WriteString(`<table><thead><tr><th>#</th><th>Score</th><th>String</th></tr></thead><tbody>`)
		// 	for i, rnk := range s.Ranked {
		// 		score := "—"
		// 		if rnk.Score != nil {
		// 			score = fmt.Sprintf("%.6f", *rnk.Score)
		// 		}
		// 		sb.WriteString(`<tr><td>` + fmt.Sprintf("%d", i+1) + `</td><td><code>` + html.EscapeString(score) + `</code></td><td><code>` + html.EscapeString(rnk.Text) + `</code></td></tr>`)
		// 	}
		// 	sb.WriteString(`</tbody></table>`)
		// }
		// sb.WriteString(`</div></details></div>`)

		sb.WriteString(`</div></section>`)
	}

	sb.WriteString(`<section id="imports" class="card"><h2>Imports</h2><div class="content">`)
	if r.Imports.Note != "" {
		sb.WriteString(`<p class="note">` + html.EscapeString(r.Imports.Note) + `</p>`)
	}
	if len(r.Imports.DLLs) == 0 {
		sb.WriteString(`<p class="badge">No imports</p>`)
	} else {
		for _, d := range r.Imports.DLLs {
			sb.WriteString(`<div class="subcard">`)
			sb.WriteString(`<h3>` + html.EscapeString(d.Name) + `</h3>`)
			if len(d.Functions) == 0 {
				sb.WriteString(`<p class="badge">No named imports</p>`)
			} else {
				sb.WriteString(`<pre>`)
				for _, fn := range d.Functions {
					sb.WriteString(html.EscapeString(fn))
					sb.WriteByte('\n')
				}
				sb.WriteString(`</pre>`)
			}
			sb.WriteString(`</div>`)
		}
	}
	sb.WriteString(`</div></section>`)

	sb.WriteString(`<section id="exports" class="card"><h2>Exports</h2><div class="content">`)
	if r.Exports.Note != "" {
		sb.WriteString(`<p class="note">` + html.EscapeString(r.Exports.Note) + `</p>`)
	}
	if len(r.Exports.Symbols) == 0 {
		sb.WriteString(`<p class="badge">No exports</p>`)
	} else {
		if r.Exports.DLLName != "" {
			sb.WriteString(`<p><span class="badge">Module</span> <code>` + html.EscapeString(r.Exports.DLLName) + `</code></p>`)
		}
		sb.WriteString(`<table><thead><tr><th>#</th><th>Ordinal</th><th>Name</th><th>RVA</th></tr></thead><tbody>`)
		for i, s := range r.Exports.Symbols {
			sb.WriteString(fmt.Sprintf(`<tr><td>%d</td><td><code>%d</code></td><td><code>%s</code></td><td><code>0x%08X</code></td></tr>`,
				i+1, s.Ordinal, html.EscapeString(s.Name), s.RVA))
		}
		sb.WriteString(`</tbody></table>`)
	}
	sb.WriteString(`</div></section>`)

	sb.WriteString(`<section id="resources" class="card"><h2>Resources</h2><div class="content">`)
	if r.Resources.Note != "" {
		sb.WriteString(`<p class="note">` + html.EscapeString(r.Resources.Note) + `</p>`)
	}
	if len(r.Resources.Types) == 0 {
		sb.WriteString(`<p class="badge">No resources</p>`)
	} else {
		sb.WriteString(`<table><thead><tr><th>Type</th><th>ID</th><th>Child entries</th></tr></thead><tbody>`)
		for _, t := range r.Resources.Types {
			sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><code>%d</code></td><td>%d</td></tr>`,
				html.EscapeString(t.TypeName), t.TypeID, t.Count))
		}
		sb.WriteString(`</tbody></table>`)
	}
	sb.WriteString(`</div></section>`)

	sb.WriteString(`</main></body></html>`)
	_, err = f.WriteString(sb.String())
	return err
}

func effLimit(n int) int {
	if n <= 0 {
		return 0
	}
	return n
}

func styles() string {
	return `<style>
:root{--bg:#0b1020;--panel:#111832;--fg:#e8eef9;--muted:#a9b4cf;--acc:#7aa2f7;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
header{padding:24px 20px;border-bottom:1px solid #1c2752;background:linear-gradient(180deg,#0c1530,#0b1020)}
h1{margin:0 0 6px;font-size:20px}
small{color:var(--muted)}
main{padding:20px}
.card{background:var(--panel);border:1px solid #1c2752;border-radius:12px;margin:0 0 16px;overflow:hidden}
.card h2,.card h3{margin:0;padding:12px 14px;border-bottom:1px solid #1c2752;background:#0c1530}
.card .content{padding:14px}
.kv{display:grid;grid-template-columns:220px 1fr;gap:8px 14px}
.kv div{padding:2px 0}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 10px;border-bottom:1px solid #1e2b5f;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}
tbody tr:hover{background:#0e1736}
pre{margin:0;white-space:pre;overflow:auto;padding:12px;background:#0c1530;border-radius:8px}
code{background:#0c1530;padding:2px 6px;border-radius:6px}
.details{margin-top:8px}
details{border:1px solid #1e2b5f;border-radius:8px;margin:8px 0;background:#0c1530}
details > summary{cursor:pointer;padding:10px 12px;user-select:none}
.badge{display:inline-block;padding:2px 8px;border:1px solid #2b3b7a;border-radius:999px;color:var(--muted);font-size:12px}
.toc a{color:var(--acc);text-decoration:none}
.toc a:hover{text-decoration:underline}
.subcard{border:1px dashed #2a3a7a;border-radius:8px;margin:10px 0;padding:10px}
.note{color:#f5d67c}
</style>`
}
