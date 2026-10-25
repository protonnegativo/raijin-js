// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every JavaScript file katana found is listed, and every
// item raijin-js extracted from them is listed with every file it appeared in, in a finding or in a group.
// Anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to save
// tokens: empty lists, the budget when nothing was cut, a count equal to the files listed, and fields at
// their documented default.
//
// raijin-js adds the item fields (rule, value, status) to findings, the kind, value and variants to
// groups, and Origin to the result.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "&" in a URL stays "&" instead of "&", which costs
// tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Target  string `json:"target"`
	Summary string `json:"summary"`
	// Origin is the scheme and host every JavaScript file shares; files are then written without it.
	Origin   string         `json:"origin,omitempty"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Finding is one item worth a look (a secret, an admin or API route, a bucket, an internal host, a source
// map) with every file it appeared in. The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the rules that made it a finding: secret, sourcemap, admin, file, bucket, internal, api,
	// auth.
	Tags []string `json:"tags"`
	// Rule is the secret rule that matched (aws-access-key, jwt...).
	Rule string `json:"rule,omitempty"`
	// Value is the path, the URL, the source map, or the secret match with the secret redacted.
	Value string `json:"value"`
	// Status is what katana got when it requested the item; left out when it did not.
	Status int `json:"status,omitempty"`
	// Locations are the files the item is in ("file:line" for a secret), numeric runs written as ranges
	// ("/static/js/chunk-[1-40].js").
	Locations []string `json:"locations"`
	// Count is the number of locations; it is set only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// Files is the number of locations, for ranking, the summary and Count; it is not written.
	Files int `json:"-"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// Group is info collapsed by kind: JavaScript files ("js"), the files of one third-party library
// ("library"), or items no rule flagged ("path", "external", "sourcemap") that appeared in the same set of
// files. Every variant listed appeared in every location listed.
type Group struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Value is the library and its version ("jquery 3.7.1").
	Value  string `json:"value,omitempty"`
	Status int    `json:"status,omitempty"`
	// Variants are the items of a path, external or sourcemap group.
	Variants  []string `json:"variants,omitempty"`
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is set only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	Files int `json:"-"`
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}
