// Package raijinjs holds the files the raijin-js binary embeds from the repository root.
package raijinjs

import _ "embed"

// Engines is engines.json: the engine versions the fixtures in bench/fixtures were produced with, and
// where to install them from.
//
//go:embed engines.json
var Engines []byte
