package web

import (
	"fmt"
	"html/template"
	"time"

	"github.com/bjones/rustdeskgui/internal/poller"
)

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"displayName": displayName,
		"formatID":    formatID,
		"relTime":     relTime,
		"deviceURI":   deviceURI,
	}
}

// formatID groups a RustDesk ID into threes, the way the client displays it.
func formatID(id string) string {
	if len(id) < 7 {
		return id
	}
	var out []byte
	for i, c := range []byte(id) {
		if i > 0 && (len(id)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, c)
	}
	return string(out)
}

// displayName is what the device is called in the list: the alias you set,
// else a reverse-DNS hostname, else the formatted ID. The OSS server never
// learns a real hostname, so the first two are the only chances at a name.
func displayName(d poller.Device) string {
	if n := d.Name(); n != "" {
		return n
	}
	return formatID(d.ID)
}

// relTime renders a timestamp as a short relative string. A nil or zero time
// means we have never observed the device online, which is distinct from
// "offline for a long time" and is worded accordingly by the caller.
func relTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := time.Since(*t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// deviceURI builds the link that opens the viewer's own RustDesk client.
// No credentials pass through this application.
func deviceURI(id string) template.URL {
	return template.URL("rustdesk://connection/new/" + id)
}
