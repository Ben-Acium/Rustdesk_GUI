# Rust Control Center

A small web console for a **self-hosted OSS RustDesk server**: see every device
registered with your `hbbs`, which ones are online right now, give them
human-readable names, and launch a connection from your own RustDesk client.

It runs alongside `hbbs`/`hbbr` and is strictly read-only toward them. It does
not proxy, replace or reconfigure your RustDesk server.

The binary, the image and the Compose service are all still called
`rustdeskgui`; "Rust Control Center" is the name the UI wears. Every command
below is unaffected by the rename.

## Why this exists

RustDesk Server **Pro** ships a web console on port 21114. The **OSS** server
does not, and it exposes no HTTP API at all. The two things it does expose are:

1. `db_v2.sqlite3` → the `peer` table: every device that has ever registered.
2. The rendezvous `OnlineRequest` message: live presence, held only in memory.

This joins those two behind a login.

## What it can and cannot show

The OSS server stores remarkably little about each device. Its `info` column is
serialized from a struct whose only field is the IP address:

```rust
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}
```

So the server has **no hostname, OS, logged-in user or client version** to
offer. The hostname a RustDesk client shows you lives in `message.proto`:

```proto
message PeerInfo {
  string username = 1;
  string hostname = 2;
  string platform = 3;
  ...
}
```

which travels inside `LoginResponse` in the **peer-to-peer session protocol**.
The client learns it directly from the remote machine after connecting; hbbs
speaks only `rendezvous.proto` and is never told. That is why naming devices is
a core feature rather than a nicety.

It is also why [Intel](#intel) exists: the console is itself a RustDesk client,
so it can connect and ask. Everything below is what the list knows *without*
connecting to anything.

| Shown | Where it comes from |
|---|---|
| RustDesk ID | `peer.id` |
| Last known IP | `peer.info` → `.ip`, normalized from the IPv4-mapped form |
| Online now | live `OnlineRequest` to hbbs |
| Last seen | this app's own history (empty until it has been running) |
| Name | your alias, else reverse DNS (see below), else the ID |
| Note | you |
| Everything else | [Intel](#intel), by connecting to the device and asking |

### Device names

Each row reads `Name (IP address)`. The name is, in order of preference:

1. **The alias you set.** Click any name to change it. Always wins.
2. **A reverse-DNS hostname**, when one is useful. A LAN machine usually
   resolves to something real (`eclipse`); a consumer ISP returns generated
   filler (`pool-71-113-27-25.rcmdva.east.verizon.net`). Records that simply
   spell out the IP address are discarded as noise, so remote devices stay
   unnamed rather than noisy. Set `RDGUI_RDNS=0` to skip the lookups entirely.
3. **The RustDesk ID**, formatted in threes.

Lookups are cached for an hour (ten minutes for misses) and run concurrently, so
they never delay a presence poll.

`peer.created_at` is the device's **first** registration, not its last — hbbs
never updates it — so it is not used as a "last seen".

## How it works

Every 20 seconds (hbbs considers a peer online for 30s after it registers):

```
hbbs db_v2.sqlite3 ──┐
   (query_only)      ├─→ poller ─→ transitions ─→ rustdeskgui.sqlite3
hbbs :21115 ─────────┘      │
   (OnlineRequest)          └─→ in-memory snapshot ─→ HTTP handlers
```

HTTP requests are served from the snapshot and never touch either database.

### The rendezvous protocol

`OnlineRequest` goes to the **NAT port**, which is the base rendezvous port
minus one — `21115` for a default server. Framing is RustDesk's `BytesCodec`: a
little-endian length prefix whose low two bits give the header size minus one,
with the length in the upper bits. The reply is a bitmask, one bit per requested
ID in request order, most-significant-bit-first within each byte.

Only two protobuf messages are needed, so they are hand-encoded in
`internal/rendezvous` with byte-exact tests rather than pulling in `protoc`.

Note that this handler performs **no authentication** — anything that can reach
the port can query presence. That is inherent to the OSS server, not to this
application.

## Deploying

Runs as one more service in the Compose stack that already runs `hbbs`/`hbbr`,
on the same host: it needs the hbbs data volume and reachability to :21115.

1. Copy this directory onto the server, next to your RustDesk compose file.
2. Generate a password hash:

   ```sh
   docker compose run --rm rustdeskgui hash
   ```

3. Put it in `.env` (single-quoted — the hash contains `$`):

   ```sh
   RDGUI_ADMIN_PASSWORD_HASH='$argon2id$v=19$m=65536,...'
   ```

4. Merge `docker-compose.yml` into your stack and bring it up:

   ```sh
   docker compose up -d --build rustdeskgui
   ```

5. Open `https://<server>:8443/`.

### Networking

The stock RustDesk compose uses `network_mode: host` so NAT detection sees real
client IPs. This service does the same, and publishes :8443 directly — there is
no `ports:` mapping to make.

Set `RDGUI_HBBS_ADDR` to the host's **LAN IP**, not `127.0.0.1`: hbbs will not
answer presence queries that arrive over loopback (see Troubleshooting). On a
bridge network instead, join that network and use `RDGUI_HBBS_ADDR=hbbs:21115`,
which resolves to the container address and works fine.

### Why the hbbs volume is mounted read-write

hbbs keeps its database in WAL mode, and SQLite cannot open a WAL database
without creating the `-shm` sidecar — even to read. A `:ro` mount therefore
fails outright. The connection is opened with `query_only(1)`, so SQLite itself
rejects any write, and the code issues none.

### TLS

Port 8443 implies HTTPS, so the service always serves TLS. With no certificate
configured it generates a self-signed one into its data volume on first run
(stable across restarts) and logs a warning. For a real certificate, set
`RDGUI_TLS_CERT` and `RDGUI_TLS_KEY`, or terminate TLS in a proxy and set
`RDGUI_INSECURE_HTTP=1`.

> **Exposure.** This is an admin view of your whole fleet behind a single
> password. If the host has a public IP, `:8443` is reachable from the internet.
> Prefer a firewall rule, a VPN/Tailscale, or binding to `127.0.0.1` and
> tunnelling, and use a real certificate if you do expose it.

## Browser client (optional)

Each device gets a **Browser** button that opens a full remote-control session
in the browser, with no RustDesk app installed. This works against the stock OSS
server — no Pro licence, no server fork.

The client itself is [CortenDesk](https://github.com/marcpope/cortendesk)'s
from-scratch TypeScript implementation of the RustDesk protocol (AGPL-3.0),
fetched and built at image build time, pinned by commit. It is served behind the
same login as the device list.

### How it connects

Browsers cannot open raw TCP or UDP, so everything is relayed. Both sockets are
proxied through **this service's own origin** rather than dialled directly:

```
browser ──wss──> rustdeskgui :8443 /ws/id    ──ws──> hbbs  :21118
browser ──wss──> rustdeskgui :8443 /ws/relay ──ws──> hbbr  :21119
```

That indirection is what makes a self-signed certificate workable. A page on
`https://` may not open `ws://`, so direct connections would need TLS on both
WebSocket ports — and a browser will not prompt to accept a certificate for a
WebSocket, it simply fails. As same-origin paths they inherit the exception you
already granted the page: **one certificate, one click**.

It also means 21118/21119 never need to be reachable from the internet, and
that hbbs sees a truthful client address: the proxy discards any `X-Real-IP` or
`X-Forwarded-For` the client sent and substitutes the peer address it actually
observed.

**hbbs enforces its key.** Without the right `licence_key` it answers
`LICENSE_MISMATCH` and nothing else happens. The key is read automatically from
`id_ed25519.pub` next to the database; override with `RDGUI_SERVER_KEY`.

### Files and terminal without the desktop

Each device also gets **Files** and **Terminal** buttons, which open a session
that negotiates **no video at all** — the remote screen is never requested, so
nothing of the desktop is shown.

RustDesk models these as separate connection types (`ConnType.FILE_TRANSFER`,
`ConnType.TERMINAL`), and the upstream client implements both as panels. It
only reaches them from inside a live desktop session, though:

```ts
getConfig: () => {
  if (!this.cfg || this.state !== 'streaming') return null;
  return buildSessionConfig(this.cfg, this.peerId, '', this.sessionHashHex, 'fileTransfer');
}
```

That gate exists so the panel can reuse the desktop login's credential and skip
a second password prompt — not because the protocol needs a desktop. Asking for
the password once on its own page lifts it.

`webclient-ext/rdgui-standalone.ts` is the entry point this project adds to
the upstream tree: it mounts their `FilePanel` with the matching `connType`.
All the real work there — dual-pane browsing, transfer queue, resume, conflict
prompts — is theirs. The image build runs `tsc --noEmit` over it, so an
upstream change to the panel's API fails the build instead of breaking at
runtime.

Leaving the password empty works here too: the device opens its accept prompt
and someone approves by hand.

Two upstream quirks are worked around from this side rather than by forking
their panel.

**Double-clicking a folder does not open it.** The panel delegates click and
dblclick to the table body and resolves the row with
`closest('tr[data-idx]')`, but its click handler re-renders the list with
`innerHTML = rows.join('')`. The first click of a double-click therefore
destroys the element the second one lands on, and because the two clicks hit
different nodes the browser never dispatches a `dblclick` at all — verified
against headless Chromium:

```
click detail=1 target=TD row=yes
click detail=2 target=TD row=yes
(no dblclick)
```

`rdgui-standalone.ts` synthesizes the missing event from the second click,
which still carries `detail === 2` and a live row. It defers a tick and stands
down if a real `dblclick` appears, so it removes itself should upstream ever
render in place, and it re-resolves the row at dispatch time because the one
seen earlier has been replaced. The same bug affects their in-session panel.

**Toolbar buttons render blank.** The client chooses between a Remix Icon
webfont glyph and its own inline SVG, detecting the font with
`document.fonts.check('16px remixicon')`. That call returns `true` for a family
that does not exist at all — in Chromium `'16px DefinitelyNotInstalledXYZ'`
reports `true` as well. The font ships with the upstream Laravel console rather
than the bundle, so the client emits `<i class="ri-...">` against a font nobody
loaded and the up, home and refresh buttons come out empty.

`static/rdclient-compat.js` narrows that false positive to the one family, and
their own SVG path takes over. Every icon defines an `svg`, so nothing is lost.

**Upstream branding is replaced, and that is also what centres the toolbar.**
The bundle's top bar is a three-column grid — brand, island, user — and an
earlier version of `static/rdclient-overrides.css` hid the brand outright. A
`display: none` grid item leaves the grid, so the island slid into column one
and sat flush left. The file now keeps the cell and relabels it instead, and
the island centres again by itself.

Only text needs relabelling: both of the bundle's `<img>` tags point at
`/rdclient/logo.png`, which this app serves from `static/logo.svg`, so they
already carry our own mark. The wordmarks are swapped in CSS; the connect
card's `alt="CortenDesk"` is the one string CSS cannot reach, so the compat
script rewrites it and retires its observer as soon as it fires. The same
script keeps the page title this server rendered rather than the one the client
assigns on connect.

Attribution is kept where it belongs: this README credits the project, and
`LICENSE` and `NOTICE` ship alongside the bundle in the image.

**The "back to devices" control is docked into that toolbar.** It is our
element on our page, not part of the bundle, so it began as a fixed-position
link at the top left — which is exactly where the brand sits, so it covered the
logo. It is now a monitor icon that the compat script moves into the toolbar's
right-hand cell beside the avatar, where it is in normal flow, cannot overlap
anything, and follows the bar when fullscreen slides the chrome away. Narrow
screens drop that cell and the toolbar to two columns, so the override adds a
third column back and hides the avatar instead: the avatar is decoration, the
button is navigation. If the bundle never renders, nothing docks and the button
stays fixed at the top left — still usable, with no logo left to cover.

The files-only and terminal-only pages carry the same control, in their own bar
rather than the bundle's, so there it needs no docking — only the matching
shape. The glyph itself lives once, in `templates/partials.html`; each page
keeps its own anchor and class, because each is styled from a different
stylesheet.

**Both panels were built to float over a live desktop, so each lets a little of
what is behind it show through — the file panel is 97% opaque, and the terminal
dims and blurs its backdrop.** With no desktop behind them that reveals the page
instead, so `static/standalone.css` overrides both to be opaque. It is loaded
after their stylesheet and reuses their `--rd-*` tokens, so the override costs
no upstream changes and follows their theme.

### A real terminal

The terminal is this project's own panel, `webclient-ext/rdgui-terminal.ts`,
rather than upstream's `TerminalPanel`.

The transport is already a PTY. The worker reports raw bytes on `terminalData`
and accepts `terminalResize` with rows and cols, so escape sequences, colour,
cursor addressing and alternate-screen programs all arrive intact. Upstream
throws that away — it runs the stream through a control-sequence stripper and
renders the leftovers into a `<pre>`, driven by a single-line command box:

```ts
case 'terminalData':
  this.appendText(this.controlStripper.push(
    this.decoder.decode(this.byteNormalizer.push(event.data), { stream: true }),
  ));
```

That is a UI decision, not a protocol limit. Our panel speaks the same worker
protocol and hands the bytes to xterm.js instead, which is what makes `vim`,
`htop`, `less`, tab completion and Ctrl-C behave the way they do in any other
terminal. It is a sibling rather than a patch: upstream keeps its panel for the
in-session dock, and ours only ever serves the standalone page.

xterm.js is installed in the image build with `npm i --no-save`, so upstream's
`package.json` and lockfile are untouched; its licence ships in the image as
`LICENSE.xterm`.

### Remembering a device's password

Tick **Remember this device's password** and you will not be asked for it
again — on the browser, files or terminal page, from any browser that signs
into this console.

**What is stored is not the password.** During the handshake the client
computes `h1 = SHA256(password ‖ salt)` and the session emits it:

```ts
const h1 = await computeLoginH1(plaintextPassword, u.hash.salt);
this.sinks.emit({ t: 'credentials', hashHex: bytesToHex(h1) });
```

`h1` is what the native RustDesk client caches on disk, and `buildSessionConfig`
accepts it in place of a password. Because the salt is per device, a stored
value opens exactly one device even when every device shares a password. The
typed password never leaves the page.

Timing matters: that event fires while the hash is being *computed*, before the
device has accepted it, so a wrong password emits one too. Upstream persists
only once the session streams, and the hook in `static/rdclient-compat.js` does
the same — it holds the value per worker and releases it on exactly that
signal, so a rejected password is never saved.

**Storage.** `h1` is sealed with XChaCha20-Poly1305 under `RDGUI_SECRET_KEY`
and kept in `device_secret`. The device ID is authenticated as additional data,
so a row moved to another device's record fails to open rather than quietly
handing that device a credential it never had. The key lives in the
environment, deliberately not in the data volume and not derived from anything
in it: a copy of the database — a backup, a stolen volume, a snapshot — is not
enough to recover any credential. It is *not* protection against someone who
already has the running host, who can read the environment either way. Leave
`RDGUI_SECRET_KEY` unset and the whole feature stays off.

**Where the browser plumbing lives.** The upstream client already implements
"save password" against `localStorage`, including the checkbox, the sign
straight in and the forget-on-untick. Rather than fork any of that, the compat
script seeds the server's copy into `localStorage` before the bundle reads it,
and mirrors the bundle's writes back up. The server is authoritative: a
credential it does not have is cleared locally rather than uploaded, so
**Password saved** → forget on the device list actually forgets instead of
being undone by the next page that still held a copy.

The device list shows which devices have one and doubles as the control to
forget it.

### Certificates

The service always serves TLS. With no certificate configured it generates a
self-signed one into its data volume, naming `RDGUI_PUBLIC_HOST` alongside
`localhost` and the loopback addresses. **Set `RDGUI_PUBLIC_HOST` to the exact
address you type in the browser** — the certificate has to cover it, because
the WebSocket rides the same origin and cannot prompt you. If an existing
certificate does not cover the configured host, it is regenerated.

A self-signed certificate is enough to get video: accepting it once makes the
page a *secure context*, which is what WebCodecs requires. For a real
certificate, set `RDGUI_TLS_CERT` and `RDGUI_TLS_KEY`.

### HTTP/2 is disabled

Deliberately. HTTP/2 has no `Upgrade` mechanism, so a WebSocket handshake
arriving over h2 loses its `Connection` and `Upgrade` headers; the proxy then
forwards a plain `GET` that hbbs closes on, surfacing as a bare `EOF`. Browsers
use HTTP/1.1 for WebSockets regardless, and nothing here benefits from
multiplexing.

### ⚠️ Exposure of 21118/21119

`hbbs`/`hbbr` trust the `X-Real-IP` and `X-Forwarded-For` headers on the
WebSocket ports. Anyone who can reach those ports directly can forge a source
address, defeating IP-based rate limiting and blocking. RustDesk's own
documentation says to expose them only through a reverse proxy that sets
`X-Real-IP` itself, and to firewall them otherwise.

Because the browser client now reaches them through this service, **they no
longer need to be open to the internet at all**:

```sh
sudo ufw deny 21118 && sudo ufw deny 21119
```

Native RustDesk clients use 21115–21117 and are unaffected.

## Intel

The device list can only show what hbbs records: an ID and an address. Intel
fills in the rest by connecting to the device and asking it directly.

Open a device from the list and press **Collect intel**. It takes a few
seconds and reports as it goes.

### Where the facts come from

Two sources, gathered in one connection:

**The handshake.** A RustDesk login response carries a `PeerInfo` with the
device's hostname, logged-in user, platform, client version and display
geometry. Every connection type gets one — including the terminal connection
Intel uses, which negotiates no video at all — so this much costs nothing
beyond connecting. These are the facts the OSS server never sees.

**A probe.** With the terminal open, one script runs and prints `key<TAB>value`
lines between two markers. It reports what the handshake cannot: CPU, memory,
disks and their usage, network interfaces and addresses, firmware and chassis
details, package counts, failed services, time zone.

There are three scripts — Linux, macOS and Windows — chosen by the platform the
handshake reported. Android has none; a device with terminal access disabled
yields handshake facts only, and says so.

Every script follows the same rules, and `internal/intel/scripts.go` is the one
file to read if you want to know exactly what runs on your machines:

- **Read only.** Nothing installs, writes, starts, stops or configures
  anything.
- **Never blocks.** Anything that could wait goes through a timeout; a hung
  command would cost the whole report.
- **Never fails loudly.** Every field is independent and optional. A missing
  binary or an unreadable file yields an empty value, not an abort — which is
  why an unprivileged run simply reports no firmware serial rather than failing.

### Why a button, and why the browser

The whole RustDesk client — rendezvous, NAT traversal, the key exchange, the
session — lives in the browser bundle. The Go server has no way to open a
session of its own, so it cannot collect on a schedule in the background. A
button on a page is where the capability actually is.

The browser is transport only. It captures the bytes between the markers and
posts them verbatim; the server parses them (`internal/intel/report.go`), bounds
them, and stores the result. One parser, server-side, where it is tested and
where a device cannot steer the code path by what it prints.

A device needs a password for Intel to connect. If this console has one saved
for it, Intel uses that and asks nothing; otherwise it prompts once, and can
remember it — see [Remembering a device's password](#remembering-a-devices-password).

### Location

`os.name` and `cpu.model` come from the machine. Location does not: it is
looked up from the public address hbbs recorded, through ip-api.com by default.

Be aware of what that means. Collecting a device sends **that device's public
IP** to a third party, over HTTP on the free tier. Nothing else goes with it —
not the device ID, not its name, not anything the probe collected — and private
and loopback addresses are never looked up at all. It locates the network, not
the machine, and the UI says so.

Set `RDGUI_GEOIP_URL=off` to disable it. Devices still report their own time
zone, which gives a coarse location with nobody else involved.

### What is stored

One JSON report per device, replaced wholesale on each collection, in this
app's own database. Unlike saved passwords it is **not** encrypted: it is
inventory, not a credential, and sealing it would make it unreadable after a
key change to protect data already visible to anyone holding a session on this
console. It does include things worth knowing about — serial numbers, MAC
addresses, usernames, listening ports — so treat a backup of the data volume
accordingly.

**Discard** on the device page deletes a report. Nothing re-collects on its own.

## Tidying the list

Devices accumulate: a machine rebuilt, a laptop returned, a test VM deleted.
Two different things can be done about one, on its detail page.

**Archive** hides it from the list. It is still there behind *Show archived*,
still fully usable, and it stays archived even if it comes back online. This is
what to use for a device you no longer care about.

**Erase record** deletes everything this console holds about it — name, note,
presence history, saved password, collected intel — and nothing else.

Neither removes the device from the RustDesk server. hbbs's `peer` table is
this application's source of truth and is opened read-only by design (see
[How it works](#how-it-works)), so an erased device **reappears in the list,
unnamed, at the next poll**. That is the honest outcome: this console can
forget a device, but it cannot unregister one. To genuinely remove a device
from the fleet you have to delete its row from hbbs's own database, with hbbs
stopped — which is outside what this application will do to your server.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RDGUI_ADMIN_PASSWORD_HASH` | *(required)* | argon2id PHC hash from `rustdeskgui hash` |
| `RDGUI_LISTEN` | `:8443` | listen address |
| `RDGUI_HBBS_ADDR` | *(required)* | hbbs NAT port; must not be loopback |
| `RDGUI_HBBS_DB` | `/hbbs-data/db_v2.sqlite3` | path to hbbs's database |
| `RDGUI_DATA_DIR` | `/data` | this app's own state |
| `RDGUI_POLL_INTERVAL` | `20s` | presence poll interval |
| `RDGUI_RDNS` | enabled | `0` disables reverse-DNS device names |
| `RDGUI_SECRET_KEY` | unset | base64 32-byte key from `rustdeskgui genkey`; enables saved device passwords. Keep it out of the data volume |
| `RDGUI_GEOIP_URL` | ip-api.com | locates a device from its public IP when Intel runs; `off` disables it |
| `RDGUI_PUBLIC_HOST` | unset | the address you type in the browser; added to the self-signed certificate |
| `RDGUI_HTTP_LISTEN` | unset | optional extra plaintext listener; drops the cookie's `Secure` flag |
| `RDGUI_SERVER_KEY` | from `id_ed25519.pub` | hbbs public key |
| `RDGUI_HBBS_WS` / `RDGUI_HBBR_WS` | `127.0.0.1:21118` / `:21119` | hbbs/hbbr WebSocket, as seen from this container |
| `RDGUI_PREFER_CODEC` | `vp8` | codec preference seeded on a client's first visit |
| `RDGUI_WEBCLIENT_DIR` | `/webclient` | built browser-client bundle |
| `RDGUI_RETAIN` | `2160h` | presence history retention (90 days) |
| `RDGUI_TLS_CERT` / `RDGUI_TLS_KEY` | *(self-signed)* | certificate to serve |
| `RDGUI_INSECURE_HTTP` | unset | `1` serves plaintext; only behind a TLS proxy |

## Troubleshooting

**The list is empty.** No client has ever registered with this server. Check
that your RustDesk clients have it set as their ID server, then connect once
from each. Confirm with:

```sh
docker compose exec hbbs sh -c 'echo "select count(*) from peer;" | sqlite3 /root/db_v2.sqlite3'
```

**Everything shows offline**, or the log repeats `closed the connection
without replying`. Probe the presence port directly, from the host, using a
non-loopback address:

```sh
docker run --rm --network host --entrypoint /usr/local/bin/rdprobe \
  rustdeskgui-rustdeskgui -addr <host-lan-ip>:21115 <device-id>
```

A connection that is accepted and then closed means one of two things:

- **You used a loopback address.** See below — this is the common one.
- **You used the wrong port.** `OnlineRequest` goes to the NAT port, the
  rendezvous port minus one (21115 by default), not 21116.

**`RDGUI_HBBS_ADDR must not be a loopback address`** on startup, or every
poll failing with EOF. hbbs deliberately treats loopback connections on the NAT
port as administrative console commands rather than rendezvous messages:

```rust
// rustdesk-server/src/rendezvous_server.rs, handle_listener2
let ip = try_into_v4(addr).ip();
if ip.is_loopback() {
    tokio::spawn(async move { /* ... handles console commands */ });
    return;
}
```

An `OnlineRequest` sent to `127.0.0.1:21115` is therefore read as a console
command, never answered, and the socket closes. This is true whether or not you
use Docker, so `RDGUI_HBBS_ADDR` must name the host's **routable** address —
its LAN IP — even though hbbs is running on the very same machine. The service
refuses to start on a loopback address rather than fail quietly every 20s.

**A device shows as a bare ID instead of a name.** Either no alias is set and
reverse DNS has nothing useful, or the PTR record was rejected as filler. Ask
the binary what it sees — this works inside the container, which has no shell:

```sh
docker compose exec rustdeskgui rustdeskgui resolve 10.0.0.14 71.113.27.25
```

```
10.176.24.40       eclipse                                   used as the device name
71.113.27.25       pool-71-113-27-25.rcmdva.east.verizon.net rejected: generated from the IP
```

Note that the container resolves names itself, so a name that exists only in the
**host's** `/etc/hosts` will not be found; it has to be in DNS. Either way, an
alias always overrides.

**The session connects, input works, but the screen is black.** Two different
causes produce this, and they are worth telling apart.

*Codec mismatch (the common one).* Offered every codec Chrome claims to decode,
a RustDesk device will often choose **AV1**. Chrome accepts an AV1 decoder
configuration readily but does not reliably render RustDesk's AV1 stream, so
frames arrive and nothing is painted — input, clipboard and file transfer keep
working, because they do not touch the video pipeline.

This service therefore seeds the client's saved codec preference with **VP8**
on first visit, that being the one observed to render reliably here. VP9 and
AV1 compress better and are worth trying from the session's display menu — the
seed is written only when no preference exists, so any choice you make there
always wins. Change the default with `RDGUI_PREFER_CODEC` (`auto`, `vp9`,
`vp8`, `h264`, `h265`, `av1`; empty disables the seeding).

If you are already past the first visit, pick the codec by hand in the
session's display controls — your saved preference is never overwritten. To
start over, clear `cortendesk.rdprefs.v1` from the site's local storage.

Confirm what a device actually sends by driving a login headlessly and counting
frames by codec:

```
[8] advertised VP9+VP8+H264+AV1 (secure-context behaviour)
    RESULT: 20 frames of av1s  (169 KiB)     <- nothing renders
[8] advertised VP9+VP8+H264 (AV1 withheld)
    RESULT: 20 frames of vp9s  (211 KiB)     <- renders
```

*No WebCodecs at all.* `VideoDecoder` only exists in a *secure context*, so on
a plain `http://` origin the client cannot decode VP8/VP9/AV1 and falls back to
playing **H.264** through Media Source Extensions, advertising H.264 and
nothing else:

```ts
} else if (mseH264Available()) {
  // No WebCodecs, but MSE can play H.264. Advertise H.264 and nothing else
  h264 = true;
}
```

The catch is on the other end: **RustDesk has no software H.264 encoder** —
H.264 and H.265 are hardware-only. A device without a usable hardware encoder
(virtual machines, most headless hosts) can only produce VP8/VP9/AV1, so again
nothing renders. Serving over HTTPS, which is the default, avoids this
entirely: accepting the self-signed certificate makes the page a secure
context. If you have deliberately moved to plain HTTP, add the origin under
`chrome://flags/#unsafely-treat-insecure-origin-as-secure`, or reach it as
`http://localhost` through an SSH tunnel.

**The browser client says the password is wrong, but you just read it off the
device.** RustDesk's one-time password **rotates after a single successful
use**. Reading it, connecting once from anywhere, then connecting again will
fail — the device is reporting its own "Wrong Password", not a client bug.

Three ways out:

- Re-read the password immediately before each connection.
- Set a **permanent password** on the device (RustDesk → Security).
- Leave the password box **empty**: the client sends an empty credential, the
  device opens its accept prompt, and the person at the keyboard allows the
  session. The page says `Waiting for the remote user to accept`.

To tell a credential problem apart from a protocol fault, drive a login
headlessly and read the device's own reply — the salt stays constant per
install while the challenge changes per connection:

```
[6] challenge received  salt=a99m8r3...  challenge=iq6ivj
[7] LOGIN ACCEPTED
    hostname: desktop-h2l5dkk   platform: Windows   version: 1.5.0
```

**No last-seen times.** Expected on a fresh install: presence history only
exists for the period this service has been running.

## Development

```sh
go test ./...                                     # unit tests
go run ./cmd/rdprobe -addr <host>:21115 <id>...   # probe a live server
```

`internal/rendezvous` is the only part that depends on RustDesk's wire format;
its tests pin the framing and bit order byte-for-byte, so an upstream change
fails loudly there rather than silently reporting every device offline.
# Rustdesk_GUI
