package intel

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

// Report is everything known about one device at one moment.
//
// Every field is optional. A report from a device whose terminal is disabled
// carries only the handshake facts; one from a locked-down Linux box carries
// no firmware serial; a probe that timed out carries whatever arrived before
// it did. Readers must render what is there rather than expect a shape.
type Report struct {
	CollectedAt time.Time `json:"collected_at"`
	// Platform is the normalized identifier the probe was chosen by.
	Platform string      `json:"platform"`
	Peer     Peer        `json:"peer"`
	Facts    Facts       `json:"facts,omitempty"`
	Probe    ProbeResult `json:"probe"`
	// ServerIP is the address hbbs last saw this device register from, copied
	// in at collection time so the report reads as a complete picture.
	ServerIP string `json:"server_ip,omitempty"`
	Geo      *Geo   `json:"geo,omitempty"`
}

// Peer is what the RustDesk handshake itself reveals, before any command runs.
// The login response carries it for every connection type, so this much is
// available even on a device that refuses terminal access.
type Peer struct {
	Hostname          string    `json:"hostname,omitempty"`
	Username          string    `json:"username,omitempty"`
	Platform          string    `json:"platform,omitempty"`
	Version           string    `json:"version,omitempty"`
	TerminalSupported bool      `json:"terminal_supported"`
	Displays          []Display `json:"displays,omitempty"`
}

type Display struct {
	Name   string  `json:"name,omitempty"`
	Width  int     `json:"width"`
	Height int     `json:"height"`
	Scale  float64 `json:"scale,omitempty"`
}

// ProbeResult records how the script step went, separately from what it
// returned. "Nothing collected" and "collected nothing" look identical in the
// facts alone, and the difference is the whole story when a report looks thin.
type ProbeResult struct {
	Ran        bool   `json:"ran"`
	Complete   bool   `json:"complete"`
	DurationMS int    `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
	// Tail is the last of what the terminal said when a probe did not finish.
	// "The probe did not finish in time" is not a diagnosis; what the shell
	// was actually doing at the time usually is.
	Tail string `json:"tail,omitempty"`
}

// maxTailLen bounds the diagnostic excerpt kept on a failed probe.
const maxTailLen = 1500

// CleanTail strips terminal control sequences from a diagnostic excerpt and
// trims it to a readable length. A raw tail is mostly cursor movement and
// colour changes, which tells the reader nothing and breaks the page it is
// rendered into.
func CleanTail(raw string) string {
	if len(raw) > MaxOutputLen {
		raw = raw[len(raw)-MaxOutputLen:]
	}
	clean := strings.TrimSpace(ansi.ReplaceAllString(raw, ""))
	// Collapse the runs of blanks that stripping leaves behind.
	clean = strings.Join(strings.Fields(clean), " ")
	if len(clean) > maxTailLen {
		clean = "…" + clean[len(clean)-maxTailLen:]
	}
	return clean
}

// Geo is a coarse location derived from the device's public address.
type Geo struct {
	Source      string  `json:"source"`
	IP          string  `json:"ip,omitempty"`
	City        string  `json:"city,omitempty"`
	Region      string  `json:"region,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Zip         string  `json:"zip,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
	AS          string  `json:"as,omitempty"`
}

// Facts is the probe's output: one key to one or more values. A key repeated
// by the script becomes a list, which is how disks, interfaces and GPUs are
// reported without the script having to know how many there will be.
type Facts map[string][]string

// Limits on what a probe may return. A device on the other end of this
// connection is not trusted to be well behaved, and the result is rendered in
// a browser and stored in a database, so the bounds are enforced here rather
// than hoped for.
const (
	maxFacts     = 400
	maxPerKey    = 64
	maxKeyLen    = 48
	maxValueLen  = 512
	MaxOutputLen = 256 << 10
)

// factKey is deliberately narrow: lowercase dotted identifiers, as the scripts
// emit. Anything else is a line that only looks like a fact.
var factKey = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z0-9_]+)*$`)

// ansi matches the escape sequences a terminal stream carries. A PTY is not a
// clean pipe: the shell colours its output, redraws lines and moves the
// cursor, and all of that arrives interleaved with what the script printed.
var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-Z\\-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)

// ParseOutput turns captured terminal output into facts.
//
// It is forgiving by design. The capture contains whatever the shell put on
// the terminal — prompts, colour codes, a stray banner from someone's .bashrc
// — and a line is only taken as a fact if it looks exactly like one. Anything
// else is dropped silently rather than treated as an error, because a device
// with a chatty login shell should still produce a usable report.
func ParseOutput(raw string) Facts {
	if len(raw) > MaxOutputLen {
		raw = raw[:MaxOutputLen]
	}
	raw = ansi.ReplaceAllString(raw, "")

	facts := make(Facts)
	for _, line := range strings.Split(raw, "\n") {
		key, value, strong := cutFact(strings.TrimRight(line, "\r "))
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" || len(key) > maxKeyLen || !factKey.MatchString(key) {
			continue
		}
		// A single space is how ordinary prose is spaced, so on its own it is
		// not enough to call something a fact — "not a fact at all" would
		// otherwise become the key "not". A tab, or the run of spaces a tab
		// expands to, is a deliberate separator. A dotted key is deliberate on
		// its own: no sentence begins "os.name".
		if !strong && !strings.Contains(key, ".") {
			continue
		}
		if len(value) > maxValueLen {
			value = value[:maxValueLen]
		}
		if _, seen := facts[key]; !seen && len(facts) >= maxFacts {
			continue
		}
		if len(facts[key]) >= maxPerKey {
			continue
		}
		facts[key] = append(facts[key], value)
	}
	return facts
}

// cutFact splits a line into key and value at the first run of whitespace,
// and reports whether that run was a deliberate separator rather than an
// ordinary space between words.
//
// The scripts print a tab, but a tab does not always survive the journey. The
// Windows console is not a pipe: ConPTY renders the program's output into a
// virtual screen and then emits the sequences to reproduce that screen, so a
// tab arrives as however many spaces it took to reach the next tab stop —
// which for a short key is several, and for a seven-character key is one.
// Splitting on whitespace rather than on a tab is what makes one parser serve
// both, and `strong` is what keeps that from swallowing prose.
//
// Values keep their own spaces, because only the first run separates them:
// "os.name Microsoft Windows 10 Pro" yields the whole product name.
func cutFact(line string) (key, value string, strong bool) {
	i := strings.IndexAny(line, " \t")
	if i <= 0 {
		return "", "", false
	}
	rest := line[i:]
	trimmed := strings.TrimLeft(rest, " \t")
	sep := rest[:len(rest)-len(trimmed)]
	return line[:i], trimmed, strings.Contains(sep, "\t") || len(sep) > 1
}

// First returns a key's single value, or "" when the key is absent. Most facts
// are scalar; this keeps callers from indexing into an empty slice.
func (f Facts) First(key string) string {
	if v := f[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Keys returns every key present, sorted. Used to render whatever a probe
// reported that this version does not have a label for, so a field added to a
// script shows up without a matching change in the UI.
func (f Facts) Keys() []string {
	out := make([]string, 0, len(f))
	for k := range f {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Summary is the one-line description of a device the list shows.
func (r *Report) Summary() string {
	parts := make([]string, 0, 3)
	if os := r.Facts.First("os.name"); os != "" {
		parts = append(parts, os)
	} else if r.Peer.Platform != "" {
		parts = append(parts, r.Peer.Platform)
	}
	if cpu := r.Facts.First("cpu.model"); cpu != "" {
		parts = append(parts, cpu)
	}
	return strings.Join(parts, " · ")
}
