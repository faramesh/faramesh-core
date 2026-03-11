// Package canonicalize implements CAR v1.0 argument normalization.
//
// Normalization rules (applied in order):
//
//  1. Null-field stripping: keys with nil values are removed.
//  2. String trimming: leading/trailing whitespace is removed.
//  3. NFKC Unicode normalization: all strings are normalized to NFKC form
//     to collapse compatibility-equivalent sequences.
//  4. Confusable character mapping: known Unicode confusable characters
//     (Cyrillic/Greek homoglyphs that look identical to Latin letters)
//     are mapped to their Latin equivalents to prevent visual spoofing.
//  5. Float precision: floating-point values are rounded to 6 significant
//     figures to eliminate IEEE 754 artifacts. 0.1+0.2=0.30000000000000004
//     becomes 0.3. NaN and Inf are replaced with 0.
//  6. Recursive: nested maps and slices are canonicalized recursively.
//  7. Key ordering: maps are returned with sorted keys for deterministic
//     canonical byte serialization.
package canonicalize

import (
	"math"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Args canonicalizes a map of tool call arguments per CAR v1.0 rules.
func Args(args map[string]any) map[string]any {
	if args == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		cv := Value(v)
		if cv != nil {
			out[k] = cv
		}
	}
	return out
}

// ToolID canonicalizes a tool identifier: trim whitespace, collapse repeated
// slashes, apply NFKC + confusable mapping, and strip invisible characters.
func ToolID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return id
	}
	// NFKC normalization.
	id = norm.NFKC.String(id)
	// Map confusable characters.
	id = mapConfusables(id)
	// Strip zero-width and invisible characters.
	var b strings.Builder
	for _, r := range id {
		if isInvisible(r) {
			continue
		}
		b.WriteRune(r)
	}
	id = b.String()
	// Collapse repeated slashes: "admin//delete" → "admin/delete".
	for strings.Contains(id, "//") {
		id = strings.ReplaceAll(id, "//", "/")
	}
	// Strip leading "./" or "../" path traversal prefixes.
	for strings.HasPrefix(id, "./") {
		id = id[2:]
	}
	for strings.HasPrefix(id, "../") {
		id = id[3:]
	}
	return id
}

// isInvisible returns true for Unicode characters that are invisible but may
// be used to bypass string matching (zero-width spaces, soft hyphens, etc.).
func isInvisible(r rune) bool {
	switch r {
	case '\u200B', // zero-width space
		'\u200C', // zero-width non-joiner
		'\u200D', // zero-width joiner
		'\u200E', // left-to-right mark
		'\u200F', // right-to-left mark
		'\u00AD', // soft hyphen
		'\uFEFF': // byte order mark / zero-width no-break space
		return true
	}
	return false
}

// SortedKeys returns the keys of a map in sorted order.
func SortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Value canonicalizes a single value recursively.
func Value(v any) any {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return normalizeString(val)
	case float64:
		return normalizeFloat(val)
	case float32:
		return normalizeFloat(float64(val))
	case map[string]any:
		return Args(val)
	case []any:
		out := make([]any, 0, len(val))
		for _, item := range val {
			cv := Value(item)
			if cv != nil {
				out = append(out, cv)
			}
		}
		return out
	default:
		return v
	}
}

// normalizeString applies NFKC normalization, confusable mapping, and trimming.
func normalizeString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// NFKC normalization collapses compatibility equivalents.
	s = norm.NFKC.String(s)
	// Map known confusable characters to their Latin equivalents.
	s = mapConfusables(s)
	return s
}

// normalizeFloat rounds to 6 significant figures and handles special values.
func normalizeFloat(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	if f == 0 {
		return 0
	}
	// 6 significant figures: determine the magnitude, then round.
	magnitude := math.Floor(math.Log10(math.Abs(f)))
	factor := math.Pow(10, 6-1-magnitude)
	return math.Round(f*factor) / factor
}

// confusableMap maps visually similar Unicode characters to their ASCII
// Latin equivalents. This prevents attacks where an agent uses Cyrillic 'а'
// (U+0430) instead of Latin 'a' (U+0061) to bypass tool-name or argument
// pattern matching in policy rules.
//
// Based on the Unicode Consortium confusables.txt, focused on the
// highest-risk Latin↔Cyrillic↔Greek homoglyphs.
var confusableMap = map[rune]rune{
	// Cyrillic → Latin
	'\u0410': 'A', // А → A
	'\u0412': 'B', // В → B
	'\u0421': 'C', // С → C
	'\u0415': 'E', // Е → E
	'\u041D': 'H', // Н → H
	'\u0406': 'I', // І → I
	'\u0408': 'J', // Ј → J
	'\u041A': 'K', // К → K
	'\u041C': 'M', // М → M
	'\u041E': 'O', // О → O
	'\u0420': 'P', // Р → P
	'\u0405': 'S', // Ѕ → S
	'\u0422': 'T', // Т → T
	'\u0425': 'X', // Х → X
	'\u0430': 'a', // а → a
	'\u0441': 'c', // с → c
	'\u0435': 'e', // е → e
	'\u04BB': 'h', // һ → h
	'\u0456': 'i', // і → i
	'\u0458': 'j', // ј → j
	'\u043E': 'o', // о → o
	'\u0440': 'p', // р → p
	'\u0455': 's', // ѕ → s
	'\u0445': 'x', // х → x
	'\u0443': 'y', // у → y

	// Greek → Latin
	'\u0391': 'A', // Α → A
	'\u0392': 'B', // Β → B
	'\u0395': 'E', // Ε → E
	'\u0397': 'H', // Η → H
	'\u0399': 'I', // Ι → I
	'\u039A': 'K', // Κ → K
	'\u039C': 'M', // Μ → M
	'\u039D': 'N', // Ν → N
	'\u039F': 'O', // Ο → O
	'\u03A1': 'P', // Ρ → P
	'\u03A4': 'T', // Τ → T
	'\u03A7': 'X', // Χ → X
	'\u03B1': 'a', // α → a (debatable but conservative)
	'\u03BF': 'o', // ο → o
	'\u03C1': 'p', // ρ → p (visual in some fonts)
}

// mapConfusables replaces known confusable characters with their Latin
// equivalents. This runs in O(n) over the string.
func mapConfusables(s string) string {
	var b strings.Builder
	changed := false
	for _, r := range s {
		if mapped, ok := confusableMap[r]; ok {
			b.WriteRune(mapped)
			changed = true
		} else {
			b.WriteRune(r)
		}
	}
	if !changed {
		return s
	}
	return b.String()
}
