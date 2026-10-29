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

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (Result, Error, Budget, Marshal and the rank tables) lives in raijin-core; these aliases
// keep the call sites unchanged. Result is written with "schema_version" as its first field.
type (
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	Write          = core.Write
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

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
