package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type gosecReport struct {
	GolangErrors map[string]json.RawMessage `json:"Golang errors"`
	Issues       []gosecIssue               `json:"Issues"`
}

type gosecIssue struct {
	RuleID string `json:"rule_id"`
	File   string `json:"file"`
	Line   string `json:"line"`
}

type govOSV struct {
	ID       string        `json:"id"`
	Affected []govAffected `json:"affected"`
}

type govAffected struct {
	Package govPackage `json:"package"`
}

type govPackage struct {
	Name string `json:"name"`
}

type govFinding struct {
	OSV          string     `json:"osv"`
	FixedVersion string     `json:"fixed_version"`
	Trace        []govTrace `json:"trace"`
}

type govTrace struct {
	Module   string      `json:"module"`
	Position govPosition `json:"position"`
}

type govPosition struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
}

func main() {
	var (
		gosecReportPath   string
		gosecBaselinePath string
		govReportPath     string
		govBaselinePath   string
		failStdlib        bool
	)

	flag.StringVar(&gosecReportPath, "gosec-report", "", "path to gosec JSON report")
	flag.StringVar(&gosecBaselinePath, "gosec-baseline", "", "path to gosec baseline allowlist")
	flag.StringVar(&govReportPath, "govuln-report", "", "path to govulncheck JSON report")
	flag.StringVar(&govBaselinePath, "govuln-baseline", "", "path to govulncheck baseline allowlist")
	flag.BoolVar(&failStdlib, "fail-stdlib", true, "fail when unknown stdlib vulnerabilities are present")
	flag.Parse()

	if gosecReportPath == "" || gosecBaselinePath == "" || govReportPath == "" || govBaselinePath == "" {
		fmt.Fprintln(os.Stderr, "all report and baseline flags are required")
		os.Exit(2)
	}

	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve workspace root: %v\n", err)
		os.Exit(1)
	}

	gosecCurrent, err := parseGosec(gosecReportPath, root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse gosec report: %v\n", err)
		os.Exit(1)
	}

	govCurrent, stdlibOSV, fixedByOSV, err := parseGovulncheck(govReportPath, root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse govulncheck report: %v\n", err)
		os.Exit(1)
	}

	gosecBaseline, err := loadBaseline(gosecBaselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load gosec baseline: %v\n", err)
		os.Exit(1)
	}
	govBaseline, err := loadBaseline(govBaselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load govulncheck baseline: %v\n", err)
		os.Exit(1)
	}

	unknownGosec := diffFindings(gosecCurrent, gosecBaseline)
	unknownGov := diffFindings(govCurrent, govBaseline)
	staleGosec := staleBaselines(gosecCurrent, gosecBaseline)
	staleGov := staleBaselines(govCurrent, govBaseline)

	hasFailure := false

	if len(unknownGosec) > 0 {
		hasFailure = true
		fmt.Fprintln(os.Stderr, "new gosec findings (not in baseline):")
		for _, finding := range unknownGosec {
			fmt.Fprintf(os.Stderr, "  - %s\n", finding)
		}
	}

	var stdlibUnknown []string
	var nonStdUnknown []string
	for _, finding := range unknownGov {
		osvID := finding
		if idx := strings.IndexByte(finding, '|'); idx > 0 {
			osvID = finding[:idx]
		}
		if stdlibOSV[osvID] {
			stdlibUnknown = append(stdlibUnknown, finding)
		} else {
			nonStdUnknown = append(nonStdUnknown, finding)
		}
	}

	if len(nonStdUnknown) > 0 {
		hasFailure = true
		fmt.Fprintln(os.Stderr, "new govulncheck findings (not in baseline):")
		for _, finding := range nonStdUnknown {
			fmt.Fprintf(os.Stderr, "  - %s\n", finding)
		}
	}

	if failStdlib && len(stdlibUnknown) > 0 {
		hasFailure = true
		fmt.Fprintln(os.Stderr, "unknown stdlib vulnerabilities detected:")
		for _, finding := range stdlibUnknown {
			osvID := finding
			if idx := strings.IndexByte(finding, '|'); idx > 0 {
				osvID = finding[:idx]
			}
			fixed := fixedByOSV[osvID]
			if fixed == "" {
				fixed = "unknown"
			}
			fmt.Fprintf(os.Stderr, "  - %s (fixed in %s)\n", finding, fixed)
		}
		fmt.Fprintln(os.Stderr, "upgrade to a patched Go toolchain and rerun govulncheck")
	}

	if len(staleGosec) > 0 {
		fmt.Fprintln(os.Stdout, "stale gosec baseline entries (safe to remove):")
		for _, finding := range staleGosec {
			fmt.Fprintf(os.Stdout, "  - %s\n", finding)
		}
	}
	if len(staleGov) > 0 {
		fmt.Fprintln(os.Stdout, "stale govulncheck baseline entries (safe to remove):")
		for _, finding := range staleGov {
			fmt.Fprintf(os.Stdout, "  - %s\n", finding)
		}
	}

	if hasFailure {
		os.Exit(1)
	}

	fmt.Printf("security baseline check passed (gosec=%d, govulncheck=%d)\n", len(gosecCurrent), len(govCurrent))
}

func parseGosec(reportPath, root string) ([]string, error) {
	// #nosec G304 -- report path is controlled by CI workflow inputs.
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, err
	}

	var report gosecReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	if len(report.GolangErrors) > 0 {
		var keys []string
		for pkg := range report.GolangErrors {
			keys = append(keys, pkg)
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("gosec had package loading errors: %s", strings.Join(keys, ", "))
	}

	unique := make(map[string]struct{}, len(report.Issues))
	for _, issue := range report.Issues {
		ruleID := strings.TrimSpace(issue.RuleID)
		if ruleID == "" {
			ruleID = "UNKNOWN"
		}

		line := strings.TrimSpace(issue.Line)
		if line == "" {
			line = "0"
		}

		fingerprint := fmt.Sprintf("%s|%s|%s", ruleID, normalizePath(issue.File, root), line)
		unique[fingerprint] = struct{}{}
	}

	return sortedKeys(unique), nil
}

func parseGovulncheck(reportPath, root string) ([]string, map[string]bool, map[string]string, error) {
	// #nosec G304 -- report path is controlled by CI workflow inputs.
	file, err := os.Open(reportPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	unique := map[string]struct{}{}
	stdlibOSV := map[string]bool{}
	fixedByOSV := map[string]string{}

	for {
		var obj map[string]json.RawMessage
		err := dec.Decode(&obj)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}

		for key, payload := range obj {
			switch strings.ToLower(key) {
			case "osv":
				var osv govOSV
				if err := json.Unmarshal(payload, &osv); err != nil {
					return nil, nil, nil, err
				}
				for _, affected := range osv.Affected {
					if strings.EqualFold(affected.Package.Name, "stdlib") {
						stdlibOSV[osv.ID] = true
						break
					}
				}
			case "finding":
				var finding govFinding
				if err := json.Unmarshal(payload, &finding); err != nil {
					return nil, nil, nil, err
				}
				if finding.OSV == "" {
					continue
				}
				if finding.FixedVersion != "" && fixedByOSV[finding.OSV] == "" {
					fixedByOSV[finding.OSV] = finding.FixedVersion
				}

				module := "unknown"
				if len(finding.Trace) > 0 && finding.Trace[0].Module != "" {
					module = finding.Trace[0].Module
				}

				filePath := "-"
				line := 0
				if len(finding.Trace) > 0 {
					last := finding.Trace[len(finding.Trace)-1]
					if last.Position.Filename != "" {
						filePath = normalizePath(last.Position.Filename, root)
						line = last.Position.Line
					}
				}

				fingerprint := fmt.Sprintf("%s|%s|%s|%d", finding.OSV, module, filePath, line)
				unique[fingerprint] = struct{}{}
			}
		}
	}

	return sortedKeys(unique), stdlibOSV, fixedByOSV, nil
}

func loadBaseline(path string) (map[string]struct{}, error) {
	// #nosec G304 -- baseline path is controlled by CI workflow inputs.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := map[string]struct{}{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func diffFindings(current []string, baseline map[string]struct{}) []string {
	var out []string
	for _, finding := range current {
		if _, ok := baseline[finding]; !ok {
			out = append(out, finding)
		}
	}
	sort.Strings(out)
	return out
}

func staleBaselines(current []string, baseline map[string]struct{}) []string {
	currentSet := map[string]struct{}{}
	for _, finding := range current {
		currentSet[finding] = struct{}{}
	}

	var out []string
	for finding := range baseline {
		if _, ok := currentSet[finding]; !ok {
			out = append(out, finding)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func normalizePath(path, root string) string {
	if path == "" {
		return "-"
	}

	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		rel, err := filepath.Rel(root, clean)
		if err == nil {
			clean = rel
		}
	}
	return filepath.ToSlash(clean)
}
