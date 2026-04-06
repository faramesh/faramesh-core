package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var offboardCmd = &cobra.Command{
	Use:   "offboard",
	Short: "Automatically remove Faramesh agent integrations",
	Long: `faramesh offboard scans a project and removes common Faramesh runtime wiring
from agent source files (imports, interceptor installs, govern wrappers, and
FARAMESH_* shell env assignments).

The command is safe-by-default and runs in dry-run mode unless --apply is set.
When applying changes, per-file backups are created with --backup-ext.`,
	Args: cobra.NoArgs,
	RunE: runOffboard,
}

var (
	offboardPath            string
	offboardApply           bool
	offboardJSON            bool
	offboardBackupExt       string
	offboardRemoveGenerated bool
)

func init() {
	offboardCmd.Flags().StringVar(&offboardPath, "path", ".", "project path to offboard")
	offboardCmd.Flags().BoolVar(&offboardApply, "apply", false, "write changes to disk (default: dry-run)")
	offboardCmd.Flags().BoolVar(&offboardJSON, "json", false, "emit machine-readable JSON report")
	offboardCmd.Flags().StringVar(&offboardBackupExt, "backup-ext", ".faramesh.bak", "backup extension for modified files")
	offboardCmd.Flags().BoolVar(&offboardRemoveGenerated, "remove-generated", false, "remove generated faramesh/policy.yaml and faramesh/policy.fpl")
}

type offboardOptions struct {
	Apply           bool
	BackupExt       string
	RemoveGenerated bool
}

type offboardFileChange struct {
	Path        string   `json:"path"`
	Rules       []string `json:"rules"`
	RemovedLine int      `json:"removed_lines"`
	BackupPath  string   `json:"backup_path,omitempty"`
}

type offboardReport struct {
	Root         string               `json:"root"`
	DryRun       bool                 `json:"dry_run"`
	FilesScanned int                  `json:"files_scanned"`
	FilesChanged int                  `json:"files_changed"`
	Changes      []offboardFileChange `json:"changes"`
	RemovedPaths []string             `json:"removed_paths,omitempty"`
}

func runOffboard(_ *cobra.Command, _ []string) error {
	root := strings.TrimSpace(offboardPath)
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve offboard path: %w", err)
	}

	report, err := offboardProject(absRoot, offboardOptions{
		Apply:           offboardApply,
		BackupExt:       offboardBackupExt,
		RemoveGenerated: offboardRemoveGenerated,
	})
	if err != nil {
		return err
	}

	if offboardJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	mode := "dry-run"
	if offboardApply {
		mode = "apply"
	}

	fmt.Printf("offboard mode: %s\n", mode)
	fmt.Printf("root: %s\n", report.Root)
	fmt.Printf("files scanned: %d\n", report.FilesScanned)
	fmt.Printf("files changed: %d\n", report.FilesChanged)

	for _, c := range report.Changes {
		rules := strings.Join(c.Rules, ",")
		fmt.Printf("- %s rules=%s removed_lines=%d", c.Path, rules, c.RemovedLine)
		if c.BackupPath != "" {
			fmt.Printf(" backup=%s", c.BackupPath)
		}
		fmt.Println()
	}
	if len(report.RemovedPaths) > 0 {
		for _, p := range report.RemovedPaths {
			fmt.Printf("- removed generated policy: %s\n", p)
		}
	}

	if !offboardApply {
		fmt.Println("run again with --apply to persist changes")
	}

	return nil
}

func offboardProject(root string, opts offboardOptions) (*offboardReport, error) {
	report := &offboardReport{Root: root, DryRun: !opts.Apply}

	files, scanned, err := collectOffboardCandidates(root)
	if err != nil {
		return nil, err
	}
	report.FilesScanned = scanned

	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		if !isLikelyText(raw) {
			continue
		}

		next, rules, removed, changed := rewriteOffboardFile(p, string(raw))
		if !changed {
			continue
		}

		change := offboardFileChange{
			Path:        p,
			Rules:       rules,
			RemovedLine: removed,
		}

		if opts.Apply {
			if opts.BackupExt != "" {
				backup := p + opts.BackupExt
				if _, statErr := os.Stat(backup); statErr == nil {
					return nil, fmt.Errorf("backup already exists for %s: %s", p, backup)
				}
				if err := os.WriteFile(backup, raw, 0o600); err != nil {
					return nil, fmt.Errorf("write backup %s: %w", backup, err)
				}
				change.BackupPath = backup
			}
			if err := writeTextFileAtomic(p, []byte(next)); err != nil {
				return nil, err
			}
		}

		report.Changes = append(report.Changes, change)
	}

	report.FilesChanged = len(report.Changes)

	if opts.RemoveGenerated {
		removed, err := offboardRemoveGeneratedPolicies(root, opts.Apply)
		if err != nil {
			return nil, err
		}
		report.RemovedPaths = removed
	}

	return report, nil
}

func collectOffboardCandidates(root string) ([]string, int, error) {
	files := make([]string, 0, 64)
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		scanned++
		if isOffboardCandidate(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("scan %s: %w", root, err)
	}
	sort.Strings(files)
	return files, scanned, nil
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", ".next", ".tmp", "tmp", "__pycache__", ".venv", "venv":
		return true
	default:
		return false
	}
}

func isOffboardCandidate(path string) bool {
	name := filepath.Base(path)
	lower := strings.ToLower(name)
	if lower == ".env" || strings.HasPrefix(lower, ".env.") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".py", ".sh", ".bash", ".zsh":
		return true
	default:
		return false
	}
}

func isLikelyText(raw []byte) bool {
	if len(raw) == 0 {
		return true
	}
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	for _, b := range raw {
		if b == 0 {
			return false
		}
	}
	return true
}

func rewriteOffboardFile(path string, src string) (string, []string, int, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".py" {
		return rewritePythonOffboard(src)
	}
	return rewriteShellOffboard(src)
}

var (
	pyImportRe         = regexp.MustCompile(`^\s*import\s+faramesh(?:\.[A-Za-z0-9_]+)*(?:\s+as\s+[A-Za-z0-9_]+)?\s*$`)
	pyFromImportRe     = regexp.MustCompile(`^\s*from\s+(faramesh(?:\.[A-Za-z0-9_]+)*)\s+import\s+(.+?)\s*$`)
	pyDecoratorNameRe  = regexp.MustCompile(`^\s*@(?:[A-Za-z0-9_]+\.)?(governed_tool|faramesh_tool|govern_agentcore_tool)\b`)
	pyEnvAssignRe      = regexp.MustCompile(`^\s*os\.environ\[(?:"|')FARAMESH_[A-Z0-9_]+(?:"|')\]\s*=`)
	pyEnvSetDefaultRe  = regexp.MustCompile(`^\s*os\.environ\.setdefault\(\s*(?:"|')FARAMESH_[A-Z0-9_]+(?:"|')\s*,`)
	pyPutEnvRe         = regexp.MustCompile(`^\s*os\.putenv\(\s*(?:"|')FARAMESH_[A-Z0-9_]+(?:"|')\s*,`)
	shellExportRe      = regexp.MustCompile(`^\s*export\s+FARAMESH_[A-Z0-9_]+\s*=`)
	shellAssignOnlyRe  = regexp.MustCompile(`^\s*FARAMESH_[A-Z0-9_]+\s*=`) // with or without continuation
	shellPrefixAssigns = regexp.MustCompile(`^\s*((?:FARAMESH_[A-Z0-9_]+=[^\s]+\s+)+)(.+)$`)
	shellUnsetRe       = regexp.MustCompile(`^\s*unset\s+(?:FARAMESH_[A-Z0-9_]+\s*)+$`)
)

func rewritePythonOffboard(src string) (string, []string, int, bool) {
	lines := strings.Split(src, "\n")
	symbolOrigins := collectFarameshSymbols(lines)
	ruleHits := map[string]int{}
	out := make([]string, 0, len(lines))
	removedLines := 0

	for i := 0; i < len(lines); {
		line := lines[i]
		trim := strings.TrimSpace(line)

		if rewritten, removedFaramesh, changed := rewritePythonImportLine(line); changed {
			if removedFaramesh > 0 {
				ruleHits["remove_faramesh_import"] += removedFaramesh
				removedLines += removedFaramesh
			}
			if rewritten != "" {
				out = append(out, rewritten)
			} else if leadingIndent(line) != "" {
				out = append(out, leadingIndent(line)+"pass  # faramesh offboard import removed")
			}
			i++
			continue
		}

		if pyImportRe.MatchString(trim) || pyFromImportRe.MatchString(trim) {
			ruleHits["remove_faramesh_import"]++
			removedLines++
			if leadingIndent(line) != "" {
				out = append(out, leadingIndent(line)+"pass  # faramesh offboard import removed")
			}
			i++
			continue
		}

		if pyDecoratorNameRe.MatchString(trim) {
			end := i
			if open := strings.Index(line, "("); open >= 0 {
				end = consumeCallBlock(lines, i, open)
			}
			ruleHits["remove_faramesh_decorator"]++
			removedLines += (end - i + 1)
			i = end + 1
			continue
		}

		if pyEnvAssignRe.MatchString(trim) || pyEnvSetDefaultRe.MatchString(trim) || pyPutEnvRe.MatchString(trim) {
			ruleHits["remove_faramesh_python_env"]++
			removedLines++
			if indent := leadingIndent(line); indent != "" {
				out = append(out, indent+"pass  # faramesh offboard env removed")
			}
			i++
			continue
		}

		if eq := strings.Index(line, "="); eq >= 0 {
			lhs := strings.TrimSpace(line[:eq])
			rhs := strings.TrimSpace(line[eq+1:])

			if matched, rule, neutral, open := matchAssignmentRule(rhs, symbolOrigins); matched {
				end := i
				if open >= 0 {
					if openRaw := strings.Index(line[eq+1:], "("); openRaw >= 0 {
						end = consumeCallBlock(lines, i, eq+1+openRaw)
					} else {
						end = consumeCallBlock(lines, i, eq+1+open)
					}
				}
				if neutral == "__extract_govern_arg__" {
					block := strings.Join(lines[i:end+1], "\n")
					if arg := extractFirstArgFromCall(block, "govern"); arg != "" {
						neutral = arg
					} else if arg := extractFirstArgFromCall(block, "faramesh.govern"); arg != "" {
						neutral = arg
					} else {
						neutral = "None"
					}
				}
				replacement := buildAssignmentReplacement(line, lhs, neutral)
				out = append(out, replacement)
				ruleHits[rule]++
				removedLines += (end - i)
				i = end + 1
				continue
			}
		}

		if matched, rule, open := matchStandaloneCallRule(trim, symbolOrigins); matched {
			end := i
			if open >= 0 {
				openPos := strings.Index(line, "(")
				if openPos >= 0 {
					end = consumeCallBlock(lines, i, openPos)
				}
			}
			ruleHits[rule]++
			removedLines += (end - i + 1)
			if indent := leadingIndent(line); indent != "" {
				out = append(out, indent+"pass  # faramesh offboard call removed")
			}
			i = end + 1
			continue
		}

		out = append(out, line)
		i++
	}

	next := strings.Join(out, "\n")
	rules := sortedRuleNames(ruleHits)
	return next, rules, removedLines, next != src
}

func matchAssignmentRule(rhs string, symbolOrigins map[string]string) (bool, string, string, int) {
	head, open := callHead(rhs)
	if head == "" || open < 0 {
		return false, "", "", -1
	}
	origin := resolveCallOrigin(head, symbolOrigins)
	if isLangchainInstallCall(head, origin) {
		return true, "neutralize_install_langchain_interceptor", "{}", open
	}
	if isAutopatchInstallCall(head, origin) {
		return true, "neutralize_autopatch_install", "[]", open
	}
	if isGovernCall(head, origin) {
		return true, "unwrap_govern_wrapper", "__extract_govern_arg__", open
	}
	return false, "", "", -1
}

func matchStandaloneCallRule(trim string, symbolOrigins map[string]string) (bool, string, int) {
	head, open := callHead(trim)
	if head == "" || open < 0 {
		return false, "", -1
	}
	origin := resolveCallOrigin(head, symbolOrigins)
	if isLangchainInstallCall(head, origin) {
		return true, "remove_install_langchain_interceptor_call", open
	}
	if isAutopatchInstallCall(head, origin) {
		return true, "remove_autopatch_install_call", open
	}
	if isGovernCall(head, origin) {
		return true, "remove_govern_call", open
	}
	return false, "", -1
}

func collectFarameshSymbols(lines []string) map[string]string {
	symbols := map[string]string{}
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if m := pyFromImportRe.FindStringSubmatch(trim); len(m) == 3 {
			module := m[1]
			items := strings.Split(m[2], ",")
			for _, item := range items {
				it := strings.TrimSpace(item)
				if it == "" || it == "*" {
					continue
				}
				parts := strings.Split(it, " as ")
				name := strings.TrimSpace(parts[0])
				alias := name
				if len(parts) == 2 {
					alias = strings.TrimSpace(parts[1])
				}
				if alias != "" {
					symbols[alias] = module + "." + name
				}
			}
			continue
		}
		if strings.HasPrefix(trim, "import ") {
			list := strings.TrimSpace(strings.TrimPrefix(trim, "import "))
			for _, item := range strings.Split(list, ",") {
				it := strings.TrimSpace(item)
				if it == "" {
					continue
				}
				parts := strings.Split(it, " as ")
				module := strings.TrimSpace(parts[0])
				alias := module
				if len(parts) == 2 {
					alias = strings.TrimSpace(parts[1])
				}
				if strings.HasPrefix(module, "faramesh") && alias != "" {
					symbols[alias] = module
				}
			}
		}
	}
	return symbols
}

func rewritePythonImportLine(line string) (string, int, bool) {
	trim := strings.TrimSpace(line)
	if !strings.HasPrefix(trim, "import ") {
		return line, 0, false
	}

	indent := leadingIndent(line)
	list := strings.TrimSpace(strings.TrimPrefix(trim, "import "))
	if list == "" {
		return line, 0, false
	}

	parts := strings.Split(list, ",")
	kept := make([]string, 0, len(parts))
	removed := 0
	for _, item := range parts {
		it := strings.TrimSpace(item)
		if it == "" {
			continue
		}
		module := strings.TrimSpace(strings.Split(it, " as ")[0])
		if strings.HasPrefix(module, "faramesh") {
			removed++
			continue
		}
		kept = append(kept, it)
	}

	if removed == 0 {
		return line, 0, false
	}
	if len(kept) == 0 {
		return "", removed, true
	}
	return indent + "import " + strings.Join(kept, ", "), removed, true
}

func callHead(expr string) (string, int) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return "", -1
	}

	open := strings.Index(s, "(")
	if open <= 0 {
		return "", -1
	}
	head := strings.TrimSpace(s[:open])
	if head == "" {
		return "", -1
	}

	for _, r := range head {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' {
			continue
		}
		return "", -1
	}
	return head, open
}

func resolveCallOrigin(head string, symbolOrigins map[string]string) string {
	if strings.Contains(head, ".") {
		parts := strings.Split(head, ".")
		base := parts[0]
		if origin, ok := symbolOrigins[base]; ok {
			if len(parts) == 1 {
				return origin
			}
			return origin + "." + strings.Join(parts[1:], ".")
		}
		return head
	}

	if origin, ok := symbolOrigins[head]; ok {
		return origin
	}
	return head
}

func isLangchainInstallCall(head, origin string) bool {
	if head == "install_langchain_interceptor" {
		return true
	}
	if strings.HasSuffix(head, ".install_langchain_interceptor") {
		return true
	}
	return strings.Contains(origin, "faramesh.adapters.langchain.install_langchain_interceptor")
}

func isAutopatchInstallCall(head, origin string) bool {
	if head == "autopatch.install" || head == "faramesh.autopatch.install" || head == "install" {
		if head == "install" {
			return strings.Contains(origin, "faramesh.autopatch.install")
		}
		return true
	}
	if strings.HasSuffix(head, ".install") && strings.Contains(origin, "faramesh.autopatch.install") {
		return true
	}
	return strings.Contains(origin, "faramesh.autopatch.install")
}

func isGovernCall(head, origin string) bool {
	if head == "faramesh.govern" {
		return true
	}
	if head == "govern" {
		return strings.Contains(origin, "faramesh.govern")
	}
	if strings.HasSuffix(head, ".govern") && strings.Contains(origin, "faramesh.govern") {
		return true
	}
	return strings.Contains(origin, "faramesh.govern")
}

func consumeCallBlock(lines []string, start, openPos int) int {
	depth := 0
	for i := start; i < len(lines); i++ {
		line := lines[i]
		jStart := 0
		if i == start {
			jStart = openPos
			if jStart < 0 || jStart >= len(line) {
				jStart = 0
			}
		}
		for j := jStart; j < len(line); j++ {
			switch line[j] {
			case '(':
				depth++
			case ')':
				depth--
				if depth <= 0 {
					return i
				}
			}
		}
	}
	return start
}

func buildAssignmentReplacement(line, lhs, rhsNeutral string) string {
	indent := leadingIndent(line)
	if rhsNeutral == "" {
		rhsNeutral = "None"
	}
	return indent + lhs + " = " + rhsNeutral
}

func extractFirstArgFromCall(expr, name string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(name) + `\s*\(\s*([A-Za-z_][A-Za-z0-9_\.]*)`)
	m := re.FindStringSubmatch(expr)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func leadingIndent(line string) string {
	idx := 0
	for idx < len(line) && (line[idx] == ' ' || line[idx] == '\t') {
		idx++
	}
	return line[:idx]
}

func rewriteShellOffboard(src string) (string, []string, int, bool) {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	ruleHits := map[string]int{}
	removedLines := 0

	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" {
			out = append(out, line)
			continue
		}

		if shellExportRe.MatchString(line) {
			ruleHits["remove_faramesh_export"]++
			removedLines++
			if indent := leadingIndent(line); indent != "" {
				out = append(out, indent+": # faramesh offboard export removed")
			}
			continue
		}

		if shellUnsetRe.MatchString(line) {
			ruleHits["remove_faramesh_unset"]++
			removedLines++
			if indent := leadingIndent(line); indent != "" {
				out = append(out, indent+": # faramesh offboard unset removed")
			}
			continue
		}

		if m := shellPrefixAssigns.FindStringSubmatch(line); len(m) == 3 {
			ruleHits["strip_faramesh_prefix_assignments"]++
			out = append(out, leadingIndent(line)+strings.TrimLeft(m[2], " \t"))
			continue
		}

		if shellAssignOnlyRe.MatchString(line) {
			ruleHits["remove_faramesh_assignment"]++
			removedLines++
			if indent := leadingIndent(line); indent != "" {
				out = append(out, indent+": # faramesh offboard assignment removed")
			}
			continue
		}

		out = append(out, line)
	}

	next := strings.Join(out, "\n")
	return next, sortedRuleNames(ruleHits), removedLines, next != src
}

func sortedRuleNames(hits map[string]int) []string {
	rules := make([]string, 0, len(hits))
	for k := range hits {
		rules = append(rules, k)
	}
	sort.Strings(rules)
	return rules
}

func writeTextFileAtomic(path string, content []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	tmpPath := path + ".offboard.tmp"
	if err := os.WriteFile(tmpPath, content, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func offboardRemoveGeneratedPolicies(root string, apply bool) ([]string, error) {
	candidates := []string{
		filepath.Join(root, "faramesh", "policy.yaml"),
		filepath.Join(root, "faramesh", "policy.fpl"),
	}
	removed := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if apply {
				if err := os.Remove(p); err != nil {
					return nil, fmt.Errorf("remove generated policy %s: %w", p, err)
				}
			}
			removed = append(removed, p)
		}
	}
	if apply {
		dir := filepath.Join(root, "faramesh")
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) == 0 {
			_ = os.Remove(dir)
		}
	}
	return removed, nil
}
