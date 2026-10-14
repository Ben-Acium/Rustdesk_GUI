package intel

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizePlatform(t *testing.T) {
	cases := map[string]string{
		"Linux": PlatformLinux, "linux": PlatformLinux, "Linux Mint": PlatformLinux,
		"Windows": PlatformWindows, "Windows 11": PlatformWindows,
		"Mac OS": PlatformMacOS, "macOS 14.1": PlatformMacOS, "Darwin": PlatformMacOS,
		"Android": PlatformAndroid,
		"":        PlatformUnknown, "Plan 9": PlatformUnknown,
	}
	for in, want := range cases {
		if got := NormalizePlatform(in); got != want {
			t.Errorf("NormalizePlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewProbeMarkersAreUnique(t *testing.T) {
	a, err := NewProbe("Linux")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewProbe("Linux")
	if err != nil {
		t.Fatal(err)
	}
	if a.Begin == b.Begin {
		t.Error("two probes shared a begin marker; stale output could be parsed as fresh")
	}
	if a.Begin == a.End {
		t.Error("begin and end markers are identical")
	}
}

// The marker must not appear in the text sent to the device: a shell echoes
// its input, and an echoed marker would be mistaken for the real thing.
func TestProbeDoesNotTransmitMarkersInClear(t *testing.T) {
	for _, platform := range []string{"Linux", "Mac OS", "Windows"} {
		p, err := NewProbe(platform)
		if err != nil {
			t.Fatal(err)
		}
		sent := strings.Join(p.Lines, "\n")
		if strings.Contains(sent, p.Begin) || strings.Contains(sent, p.End) {
			t.Errorf("%s: a marker appears verbatim in the transmitted script", platform)
		}
	}
}

func TestProbeLinesAreShortEnoughForATerminal(t *testing.T) {
	// MAX_CANON is 4096 on Linux and lower elsewhere; anything past it is
	// discarded by the line discipline rather than delivered.
	const limit = 2048
	for _, platform := range []string{"Linux", "Mac OS"} {
		p, err := NewProbe(platform)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range p.Lines {
			if len(l) > limit {
				t.Errorf("%s: line %d is %d bytes, over the %d limit", platform, i, len(l), limit)
			}
		}
	}
}

func TestUnsupportedPlatformHasNoScript(t *testing.T) {
	p, err := NewProbe("Android")
	if err != nil {
		t.Fatal(err)
	}
	if p.Supported || len(p.Lines) > 0 {
		t.Error("Android should carry no script: the handshake facts are all we can get")
	}
}

func TestParseOutputIgnoresTerminalNoise(t *testing.T) {
	raw := "user@box:~$ \x1b[1;32mcolour\x1b[0m\r\n" +
		"os.name\tDebian GNU/Linux 12\r\n" +
		"not a fact at all\r\n" +
		"Welcome to your machine!\r\n" +
		"disk\t/|ext4|100|50|50|50%\r\n" +
		"disk\t/home|ext4|200|10|190|5%\r\n" +
		"BADKEY\tvalue\r\n" +
		"empty.value\t\r\n"

	f := ParseOutput(raw)
	if got := f.First("os.name"); got != "Debian GNU/Linux 12" {
		t.Errorf("os.name = %q", got)
	}
	if got := len(f["disk"]); got != 2 {
		t.Errorf("disk count = %d, want 2", got)
	}
	// "not a fact at all" must not become the key "not": a bare word followed
	// by one space is a sentence, not a separator.
	for _, bad := range []string{"BADKEY", "empty.value", "not", "welcome"} {
		if _, ok := f[bad]; ok {
			t.Errorf("%q should not have parsed as a fact", bad)
		}
	}
	if len(f) != 2 {
		t.Errorf("parsed %d keys, want exactly os.name and disk: %v", len(f), f.Keys())
	}
}

func TestParseOutputBoundsAHostileDevice(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxPerKey*3; i++ {
		b.WriteString("disk\tvalue\n")
	}
	b.WriteString("long\t" + strings.Repeat("x", maxValueLen*2) + "\n")
	f := ParseOutput(b.String())

	if got := len(f["disk"]); got != maxPerKey {
		t.Errorf("disk values = %d, want capped at %d", got, maxPerKey)
	}
	if got := len(f.First("long")); got != maxValueLen {
		t.Errorf("value length = %d, want truncated to %d", got, maxValueLen)
	}
}

// TestLinuxProbeAgainstThisMachine runs the real script the way a device would
// receive it — assembled from chunks, base64-decoded, piped into /bin/sh — and
// checks it reports facts about the machine running the test.
//
// The point is not the specific values but that the whole chain holds: the
// chunking is reassembled correctly, the decode works, every command is
// syntactically valid, and nothing hangs.
func TestLinuxProbeAgainstThisMachine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the Linux probe can only be exercised on Linux")
	}
	if _, err := exec.LookPath("base64"); err != nil {
		t.Skip("base64 is not installed")
	}

	p, err := NewProbe("Linux")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(strings.Join(p.Lines, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running the probe failed: %v", err)
	}

	text := string(out)
	_, after, found := strings.Cut(text, p.Begin)
	if !found {
		t.Fatalf("no begin marker in output:\n%s", text)
	}
	body, _, found := strings.Cut(after, p.End)
	if !found {
		t.Fatalf("no end marker; the script did not finish:\n%s", text)
	}

	f := ParseOutput(body)
	// Facts every Linux machine can answer, from files that always exist.
	for _, key := range []string{
		"probe.platform", "host.name", "os.kernel", "os.arch",
		"os.uptime_s", "cpu.model", "cpu.threads", "mem.total_kb",
	} {
		if f.First(key) == "" {
			t.Errorf("no value for %s; probe returned: %v", key, f.Keys())
		}
	}
	if len(f["disk"]) == 0 {
		t.Error("no disks reported")
	}
	if len(f["net.iface"]) == 0 {
		t.Error("no network interfaces reported")
	}
	t.Logf("collected %d keys: %v", len(f), f.Keys())
	t.Logf("os=%q cpu=%q mem=%skB disks=%d",
		f.First("os.name"), f.First("cpu.model"), f.First("mem.total_kb"), len(f["disk"]))
}

// A real capture from a Windows 10 device, taken off the wire. The tabs the
// script printed are not in it: ConPTY re-renders the program's output into a
// screen and reproduces that screen, so each tab arrived as however many
// spaces it took to reach the next tab stop. Parsing this is the whole reason
// cutFact splits on whitespace rather than on "\t".
const windowsCapture = "\r\n" +
	"probe.platform  windows\r\n" +
	"host.name       DESKTOP-H2L5DKK\r\n" +
	"host.fqdn       DESKTOP-H2L5DKK.WORKGROUP\r\n" +
	"user.current    DESKTOP-H2L5DKK\\tester\r\n" +
	"os.name Microsoft Windows 10 Pro\r\n" +
	"os.version      10.0.19045\r\n" +
	"os.uptime_s     6466\r\n" +
	"time.zone       Eastern Standard Time\r\n" +
	"cpu.model       Intel(R) Core(TM) i9-10900KF CPU @ 3.70GHz\r\n" +
	"mem.total_kb    12713012\r\n" +
	"hw.serial       VMware-56 4d e1 f8 f2 b5 28 c9-83 1d 46 68 0b ea bb 43\r\n" +
	"disk    C:|NTFS|62257392|29103924|33153468|47%\r\n" +
	"net.iface       Ethernet0|00-0C-29-EA-BB-43|Up\r\n" +
	"gpu     VMware SVGA 3D\r\n" +
	"os.updates      KB5126256\r\n"

func TestParseOutputHandlesTabsExpandedToSpaces(t *testing.T) {
	f := ParseOutput(windowsCapture)

	want := map[string]string{
		"probe.platform": "windows",
		"host.name":      "DESKTOP-H2L5DKK",
		"os.version":     "10.0.19045",
		"os.uptime_s":    "6466",
		"mem.total_kb":   "12713012",
		"gpu":            "VMware SVGA 3D",
		"os.updates":     "KB5126256",
	}
	for key, value := range want {
		if got := f.First(key); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}

	// A value keeps its own spaces: only the first run separates it from the key.
	if got := f.First("os.name"); got != "Microsoft Windows 10 Pro" {
		t.Errorf("os.name = %q; the value was cut at an interior space", got)
	}
	if got := f.First("cpu.model"); got != "Intel(R) Core(TM) i9-10900KF CPU @ 3.70GHz" {
		t.Errorf("cpu.model = %q", got)
	}
	if got := f.First("hw.serial"); got != "VMware-56 4d e1 f8 f2 b5 28 c9-83 1d 46 68 0b ea bb 43" {
		t.Errorf("hw.serial = %q", got)
	}
	if len(f["disk"]) != 1 || len(f["net.iface"]) != 1 {
		t.Errorf("structured values were lost: disk=%v iface=%v", f["disk"], f["net.iface"])
	}
	if len(f) != 15 {
		t.Errorf("parsed %d keys, want 15: %v", len(f), f.Keys())
	}
}

// The echo of what we typed sits either side of the markers, and a shell
// prompt follows the last line. None of it may become a fact.
func TestParseOutputIgnoresShellEcho(t *testing.T) {
	noise := "PS C:\\Users\\tester> $b+='JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4A'\r\n" +
		">> $b=''\r\n" +
		"PS C:\\Users\\tester>\r\n" +
		"user@box:~$ exec /bin/sh\r\n" +
		"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux)\r\n" +
		"os.name Ubuntu 22.04.3 LTS\r\n"

	f := ParseOutput(noise)
	if len(f) != 1 || f.First("os.name") != "Ubuntu 22.04.3 LTS" {
		t.Errorf("parsed %v, want only os.name", f)
	}
}
