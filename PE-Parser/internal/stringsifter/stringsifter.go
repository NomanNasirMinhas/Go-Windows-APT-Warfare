package stringsifter

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type ScoredString struct {
	Text     string
	ScorePtr *float64
}

func EnsureAvailable(offerInstall bool, assumeYes bool, verbose bool) (string, string) {
	if path, _ := exec.LookPath("rank_strings"); path != "" {
		return path, ""
	}
	if hasPython() {
		return "", ""
	}
	if !offerInstall {
		return "", "StringSifter (rank_strings) not found. " + installHint()
	}
	if verbose && !assumeYes {
		fmt.Println("[-] StringSifter (rank_strings) not found.")
		fmt.Println("    " + installHint())
		fmt.Print("    Proceed with installation? [y/N]: ")
		var resp string
		fmt.Scanln(&resp)
		resp = strings.TrimSpace(strings.ToLower(resp))
		if resp != "y" && resp != "yes" {
			return "", "Skipped StringSifter installation."
		}
	}
	if err := runInstall(); err != nil {
		return "", fmt.Sprintf("StringSifter install failed: %v", err)
	}
	if path, _ := exec.LookPath("rank_strings"); path != "" || hasPython() {
		return path, ""
	}
	return "", "StringSifter still not available after install."
}

func Rank(input []string, limit int, minScore float64) ([]ScoredString, string) {
	useModule := false
	cmdName, args := "rank_strings", []string{}
	if _, err := exec.LookPath("rank_strings"); err != nil {
		useModule = true
		py, pyArgs := pythonCmd()
		cmdName = py
		args = append(pyArgs, "-m", "stringsifter.rank_strings")
	}
	args = append(args, "--scores")
	if limit > 0 {
		args = append(args, "--limit", strconv.Itoa(limit))
	}
	if minScore > 0 {
		args = append(args, "--min-score", fmt.Sprintf("%.6f", minScore))
	}
	cmd := exec.Command(cmdName, args...)
	var stdin bytes.Buffer
	for _, s := range input {
		stdin.WriteString(s)
		stdin.WriteByte('\n')
	}
	cmd.Stdin = &stdin
	out, err := cmd.Output()
	if err != nil {
		name := "rank_strings"
		if useModule {
			name = "python -m stringsifter.rank_strings"
		}
		return nil, fmt.Sprintf("Failed running %s: %v", name, err)
	}
	lines := strings.Split(string(out), "\n")
	var ranked []ScoredString
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		sp := strings.IndexByte(t, ' ')
		if sp > 0 {
			if sc, err := strconv.ParseFloat(t[:sp], 64); err == nil {
				txt := strings.TrimSpace(t[sp+1:])
				val := sc
				ranked = append(ranked, ScoredString{Text: txt, ScorePtr: &val})
				continue
			}
		}
		ranked = append(ranked, ScoredString{Text: t, ScorePtr: nil})
	}
	return ranked, ""
}

func hasPython() bool {
	if _, err := exec.LookPath("python3"); err == nil {
		return true
	}
	if _, err := exec.LookPath("py"); err == nil {
		return true
	}
	if _, err := exec.LookPath("python"); err == nil {
		return true
	}
	return false
}

func pythonCmd() (string, []string) {
	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("py"); err == nil {
			return "py", []string{"-3"}
		}
	}
	if _, err := exec.LookPath("python3"); err == nil {
		return "python3", nil
	}
	return "python", nil
}

func installHint() string {
	switch runtime.GOOS {
	case "windows":
		return `Install: py -3 -m pip install --user --upgrade pip && py -3 -m pip install --user stringsifter`
	case "darwin":
		return `Install: python3 -m pip install --user --upgrade pip && python3 -m pip install --user stringsifter  (if missing: brew install python)`
	default:
		return `Install: python3 -m pip install --user --upgrade pip && python3 -m pip install --user stringsifter`
	}
}

func runInstall() error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "py -3 -m pip install --user --upgrade pip && py -3 -m pip install --user stringsifter")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	case "darwin":
		cmd := exec.Command("bash", "-lc", "python3 -m pip install --user --upgrade pip && python3 -m pip install --user stringsifter")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	default:
		cmd := exec.Command("bash", "-lc", "python3 -m pip install --user --upgrade pip && python3 -m pip install --user stringsifter")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
}
