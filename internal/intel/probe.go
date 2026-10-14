// Package intel collects and stores a device's inventory: hardware, software,
// network and location.
//
// None of it comes from the RustDesk server. The OSS server's peer table holds
// an ID and an IP and nothing else — not a hostname, not an OS, not a version
// (see internal/hbbs). Two other sources fill that gap:
//
//   - The handshake. A RustDesk login response carries a PeerInfo with the
//     device's hostname, logged-in username, platform and client version. Every
//     connection type gets one, including the terminal connection that runs no
//     video at all, so this much costs nothing beyond connecting.
//
//   - A probe. With a terminal connection open, one short read-only script
//     reports what the handshake cannot: CPU, memory, disks, interfaces,
//     firmware, package counts, timezone.
//
// The scripts live here rather than in the browser bundle so that changing what
// Intel asks is a change to this file alone. The bundle is built from a pinned
// upstream checkout inside the Docker image; a probe tweak should not require
// rebuilding it.
package intel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Shell names the interpreter a script is written for. The collector uses it
// to decide how to feed the script into the PTY.
const (
	ShellPOSIX      = "sh"
	ShellPowerShell = "powershell"
)

// Platform identifiers, normalized from the handshake's PeerInfo.platform.
const (
	PlatformLinux   = "linux"
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
	PlatformAndroid = "android"
	PlatformUnknown = "unknown"
)

// Probe is one platform's collection script together with the markers that
// delimit its output in the terminal stream.
type Probe struct {
	Platform string `json:"platform"`
	Shell    string `json:"shell"`
	// Begin and End bracket the probe's output. The script prints them from
	// pieces assembled at run time, so a shell echoing the command line back
	// at us cannot be mistaken for the output it is about to produce.
	Begin string `json:"begin"`
	End   string `json:"end"`
	// Prelude is sent first, one line at a time with a pause after each, and
	// a longer pause before Lines. It puts the far end into a shell that can
	// take the script without drowning in its own echo; see posixLines.
	Prelude []string `json:"prelude"`
	// Lines are fed into the PTY one per line, in order.
	Lines []string `json:"lines"`
	// Supported is false for platforms with no probe. The handshake facts are
	// still collected; only the script step is skipped.
	Supported bool `json:"supported"`
}

// NormalizePlatform maps the handshake's platform string onto our identifiers.
// RustDesk reports "Windows", "Linux", "Mac OS" and "Android"; matching loosely
// means an unexpected spelling degrades to unknown rather than misdispatching.
func NormalizePlatform(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case l == "":
		return PlatformUnknown
	case strings.Contains(l, "android"):
		return PlatformAndroid
	// Before the Windows test, which "Darwin" would otherwise satisfy.
	case strings.Contains(l, "mac"), strings.Contains(l, "darwin"), strings.Contains(l, "ios"):
		return PlatformMacOS
	case strings.Contains(l, "win"):
		return PlatformWindows
	case strings.Contains(l, "linux"), strings.Contains(l, "bsd"), strings.Contains(l, "unix"):
		return PlatformLinux
	}
	return PlatformUnknown
}

// NewProbe builds the script for a platform, with fresh markers.
//
// The nonce is per call rather than fixed so that output left over from an
// earlier collection — a reconnected persistent terminal, a replayed buffer —
// cannot be parsed as this one's.
func NewProbe(platform string) (Probe, error) {
	nonce, err := newNonce()
	if err != nil {
		return Probe{}, err
	}

	p := Probe{
		Platform: NormalizePlatform(platform),
		Begin:    "RDGUI." + nonce + ".BEGIN",
		End:      "RDGUI." + nonce + ".END",
	}

	switch p.Platform {
	case PlatformLinux:
		p.Shell, p.Supported = ShellPOSIX, true
		p.Prelude, p.Lines = posixPrelude, posixLines(linuxScript, p, "base64 -d")
	case PlatformMacOS:
		// BSD base64 spells the decode flag -D. Recent versions also accept
		// -d, older ones do not, so use the one that works everywhere.
		p.Shell, p.Supported = ShellPOSIX, true
		p.Prelude, p.Lines = posixPrelude, posixLines(macScript, p, "base64 -D")
	case PlatformWindows:
		p.Shell, p.Supported = ShellPowerShell, true
		p.Prelude, p.Lines = powerShellPrelude, powerShellLines(windowsScript, p)
	default:
		// Android has no shell worth probing through RustDesk, and an unknown
		// platform is not something to guess a syntax for.
		p.Shell, p.Lines, p.Supported = "", nil, false
	}
	return p, nil
}

func newNonce() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("intel: generate probe nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// chunkLen bounds how much of the encoded script goes on one line.
//
// A terminal in canonical mode discards input past MAX_CANON, which is 4096
// bytes on Linux and smaller elsewhere. An interactive shell usually puts the
// line discipline in raw mode and reads arbitrarily long lines, but "usually"
// is not something to rely on when the failure mode is a silently truncated
// script, so the encoded form is assembled from short pieces.
const chunkLen = 512

// chunkLenPowerShell is smaller because Windows echoes more per character; see
// powerShellLines.
const chunkLenPowerShell = 240

// posixPrelude gets the far end into a shell that will not fight us.
//
// Both lines earn their place. `exec /bin/sh` replaces whatever login shell
// the device uses — fish and csh cannot parse the assignments below, and bash's
// readline repaints the whole line after every keystroke, which turns a 6 KB
// script into megabytes of echo. Plain sh has no line editor, so the only echo
// left is the kernel's, and `stty -echo` turns that off too.
//
// Each line is sent on its own with a pause, because a shell that has read
// ahead into its own buffer loses whatever is sitting there when it execs.
var posixPrelude = []string{
	"exec /bin/sh",
	"stty -echo 2>/dev/null",
}

// powerShellPrelude unloads PSReadLine.
//
// It is the single reason the Windows probe could not be delivered: PSReadLine
// repaints the entire input line, in colour, after every character received.
// A 6 KB command produced 94 KB of repaints in fifty seconds and had got
// through roughly two hundred characters. Without it the console echoes
// linearly and the same command arrives in about a second.
var powerShellPrelude = []string{
	"Remove-Module -Name PSReadLine -Force -ErrorAction SilentlyContinue",
}

// posixLines wraps a shell script as base64 assembled across several short
// lines and decoded into a fresh /bin/sh.
//
// Sending the script as plain text would have three problems, and encoding it
// removes all three at once:
//
//   - The shell echoes back what it is given. A script that prints a marker
//     would have that marker appear twice — once in the echo, once in the
//     output — and the echo comes first.
//   - Every line typed at an interactive shell is followed by a prompt, which
//     lands in the middle of the output being parsed.
//   - The syntax has to survive whatever login shell the device uses. Only the
//     one wrapper line here does; the script itself is read by the /bin/sh it
//     is piped into, whatever the login shell happens to be.
func posixLines(script string, p Probe, decode string) []string {
	enc := encodeScript(script, p)

	// A quoted empty assignment, then append-in-place. "$B" stays correct for
	// a value of any length, where a single long assignment would not.
	lines := []string{"B=''"}
	for _, c := range chunks(enc, chunkLen) {
		lines = append(lines, "B=\"$B\"'"+c+"'")
	}
	return append(lines, "printf '%s' \"$B\" | "+decode+" | /bin/sh")
}

// powerShellLines builds the script up a piece at a time and then runs it as
// -EncodedCommand.
//
// -EncodedCommand is what makes the script survive two levels of Windows
// command-line parsing without any quoting at all, and running it as a child
// process means it executes with -NoProfile in a clean session rather than
// through Invoke-Expression, which a constrained-language host may refuse.
//
// What it must not be is one long line. Even with PSReadLine gone, the console
// echoes every character back across the session, and -EncodedCommand's
// UTF-16 base64 is roughly 2.7 bytes for every byte of script. Assembling it
// from short pieces keeps any single line small.
func powerShellLines(script string, p Probe) []string {
	s := substitute(script, p)

	// -EncodedCommand takes base64 of UTF-16LE, which is what PowerShell means
	// by "Unicode".
	u16 := make([]byte, 0, len(s)*2)
	for _, r := range utf16.Encode([]rune(s)) {
		u16 = append(u16, byte(r), byte(r>>8))
	}

	lines := []string{"$b=''"}
	for _, c := range chunks(base64.StdEncoding.EncodeToString(u16), chunkLenPowerShell) {
		lines = append(lines, "$b+='"+c+"'")
	}
	return append(lines,
		"powershell -NoLogo -NoProfile -NonInteractive -EncodedCommand $b")
}

func encodeScript(script string, p Probe) string {
	return base64.StdEncoding.EncodeToString([]byte(substitute(script, p)))
}

// substitute fills in the markers. They are written into the script rather
// than assembled by it: because the script is never echoed in plain text,
// there is no echo for them to collide with.
func substitute(script string, p Probe) string {
	r := strings.NewReplacer("__BEGIN__", p.Begin, "__END__", p.End)
	return r.Replace(strings.TrimSpace(script)) + "\n"
}

func chunks(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}
