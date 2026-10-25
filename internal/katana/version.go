package katana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	raijinjs "github.com/protonnegativo/raijin-js"
)

// Engine is one entry of engines.json: the version the fixtures were produced with, and where it
// installs from (exactly one of Go, Pip, System).
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Engines parses the embedded engines.json.
func Engines() (map[string]Engine, error) {
	var m map[string]Engine
	if err := json.Unmarshal(raijinjs.Engines, &m); err != nil {
		return nil, fmt.Errorf("engines.json: %w", err)
	}
	return m, nil
}

// Install is the command that installs the given version of the engine.
func (e Engine) Install(name, version string) string {
	switch {
	case e.Go != "":
		return "go install " + e.Go + "@v" + version
	case e.Pip != "":
		return "pipx install " + e.Pip + "==" + version
	case e.System != "":
		return "install the " + e.System + " " + version + " package"
	}
	return "install " + name + " " + version
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion finds the first X.Y.Z (or vX.Y.Z) in a version command's output. katana -version writes
// its banner, then "[INF] Current version: v1.1.2", to stderr.
func ParseVersion(out string) (v [3]int, ok bool) {
	m := versionRe.FindStringSubmatch(out)
	if m == nil {
		return v, false
	}
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// Untested is true when the installed version has another major version than the tested one, or is
// older. A newer minor or patch release of the same major is not reported: the weekly drift job tests it.
func Untested(installed, tested [3]int) bool {
	if installed[0] != tested[0] {
		return true
	}
	for i := 1; i < 3; i++ {
		if installed[i] != tested[i] {
			return installed[i] < tested[i]
		}
	}
	return false
}

// VersionHint runs "<bin> -version" (3s at most) and returns a hint when the installed katana is not a
// version raijin-js was tested with, or "" when it is, or when the version cannot be told.
func VersionHint(ctx context.Context, bin string) string {
	engines, err := Engines()
	if err != nil {
		return ""
	}
	e, ok := engines["katana"]
	if !ok {
		return ""
	}
	tested, ok := ParseVersion(e.Version)
	if !ok {
		return ""
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "-version", "-duc", "-nc")
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // the output is enough, whatever the exit status
	installed, ok := ParseVersion(out.String())
	if !ok || !Untested(installed, tested) {
		return ""
	}
	v := fmt.Sprintf("%d.%d.%d", installed[0], installed[1], installed[2])
	return "katana " + v + " is not the tested " + e.Version + "; results may be incomplete. Install the tested version: " + e.Install("katana", e.Version)
}
