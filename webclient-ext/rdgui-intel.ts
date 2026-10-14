// rustdeskgui: Intel — collect one device's inventory from the browser.
//
// Why the browser does this at all, rather than the Go server collecting on a
// schedule: the RustDesk client is the browser. Rendezvous, NAT traversal, the
// key exchange and the whole encrypted session live in this bundle, so the
// server has no way to open a session of its own. A button on a page is not a
// compromise here; it is where the capability actually is.
//
// Two sources, in one connection:
//
//   1. The handshake. A login response carries PeerInfo — hostname, logged-in
//      user, platform, client version, display geometry — for every connection
//      type. The OSS RustDesk server stores none of that (its peer table holds
//      an ID and an IP), so this is the only place it can be had, and it costs
//      nothing beyond connecting.
//
//   2. A probe. With the terminal open, one read-only script reports what the
//      handshake cannot. The script comes from the server, per platform, with
//      markers generated per request; see internal/intel.
//
// This module is transport. It captures bytes between the markers and hands
// them over verbatim — it does not parse them. Parsing happens server-side in
// internal/intel, where it is tested and where a device cannot steer the code
// path by what it prints.
import {
  buildSessionConfig,
  resolveWorkerUrl,
  type RdGlobalConfig,
} from './common';
import { disconnectIndependentWorker } from './advanced-worker-lifecycle';
import type { SessionEvent, UiCommand } from '../core/contracts';

const utf8 = new TextEncoder();

/** How long to wait for the session to reach 'streaming'. */
const CONNECT_TIMEOUT_MS = 45_000;
/** How long to wait for the probe's end marker once the shell is open. */
const PROBE_TIMEOUT_MS = 45_000;
/** Pause between script lines, so the remote line discipline keeps up. */
const LINE_DELAY_MS = 40;
/** Pause after each prelude line. `exec` discards whatever the old shell has
 *  already read, so the next line must not be in flight when it runs. */
const PRELUDE_DELAY_MS = 500;
/** Give the shell a moment to finish drawing its prompt before typing. */
const SETTLE_MS = 400;
/** Bound the capture; the server bounds it again before parsing. */
const MAX_CAPTURE = 512 * 1024;

type Probe = {
  platform: string;
  shell: string;
  begin: string;
  end: string;
  prelude: string[];
  lines: string[];
  supported: boolean;
};

type PeerFacts = {
  hostname: string;
  username: string;
  platform: string;
  version: string;
  terminal_supported: boolean;
  displays: Array<{ name: string; width: number; height: number; scale: number }>;
};

export type CollectResult = {
  platform: string;
  peer: PeerFacts;
  output: string;
  /** Raw terminal output, sent only when the probe failed. The server strips
   *  the control sequences and keeps the tail, so a failure can be read rather
   *  than merely reported. */
  tail: string;
  probe: { ran: boolean; complete: boolean; duration_ms: number; error: string };
};

export type CollectOptions = {
  peerId: string;
  /** Typed password. Ignored when savedHash is set. Empty asks the device. */
  password?: string;
  /** h1 = SHA256(password||salt), when this console has one stored. */
  savedHash?: string;
  /** Fetches the probe for a platform. Supplied by the page so this module
   *  needs no knowledge of the console's URLs or its CSRF scheme. */
  fetchProbe(platform: string): Promise<Probe>;
  onProgress?(message: string): void;
};

const emptyPeer = (): PeerFacts => ({
  hostname: '',
  username: '',
  platform: '',
  version: '',
  terminal_supported: false,
  displays: [],
});

/**
 * Run one collection.
 *
 * Resolves with whatever was gathered, including when the probe fails: a
 * report with only handshake facts is a useful report, and the caller is told
 * what went wrong through `probe.error`. It rejects only when the session
 * itself could not be established, because then there is nothing to report.
 */
export function collect(opts: CollectOptions): Promise<CollectResult> {
  const cfg = (globalThis as { __RD__?: RdGlobalConfig }).__RD__;
  if (!cfg) return Promise.reject(new Error('Client configuration is missing.'));

  const progress = (m: string): void => opts.onProgress?.(m);

  return new Promise<CollectResult>((resolve, reject) => {
    const peer = emptyPeer();
    const decoder = new TextDecoder('utf-8');
    let capture = '';
    let probe: Probe | undefined;
    let terminalId = 0;
    let opened = false;
    let settled = false;
    let probeStarted = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const workerUrl = resolveWorkerUrl(cfg.workerUrl, null, import.meta.url);
    const worker = new Worker(workerUrl, { type: 'module' });

    const stop = (): void => {
      if (timer !== undefined) clearTimeout(timer);
      try {
        if (opened) worker.postMessage({ c: 'terminalClose', terminalId } satisfies UiCommand);
      } catch {
        /* the worker may already be gone */
      }
      disconnectIndependentWorker(worker);
    };

    const fail = (message: string): void => {
      if (settled) return;
      settled = true;
      stop();
      reject(new Error(message));
    };

    // Resolve with what we have. `error` is empty only when the end marker
    // arrived, so a truncated capture is never presented as a whole one.
    const finish = (error: string): void => {
      if (settled) return;
      settled = true;
      stop();

      const complete = error === '' && probe !== undefined;
      // A run that stopped early still carries whatever facts arrived before
      // it did, so take everything after the begin marker rather than
      // discarding the lot. The server parses leniently and ignores the
      // half-written line at the end.
      const output = probe ? sliceBetween(capture, probe.begin, probe.end) : '';
      resolve({
        platform: peer.platform,
        peer,
        output,
        // Enough to diagnose with, not the whole transcript: a shell that
        // echoes badly can produce a hundred kilobytes of repaints.
        tail: complete ? '' : capture.slice(-8000),
        probe: {
          ran: probeStarted > 0,
          complete,
          duration_ms: probeStarted > 0 ? Date.now() - probeStarted : 0,
          error,
        },
      });
    };

    const arm = (ms: number, onLapse: () => void): void => {
      if (timer !== undefined) clearTimeout(timer);
      timer = setTimeout(onLapse, ms);
    };

    arm(CONNECT_TIMEOUT_MS, () => fail('Timed out connecting to the device.'));

    worker.onerror = () => fail('The session worker failed to start.');

    worker.onmessage = (event: MessageEvent<SessionEvent>) => {
      const ev = event.data;
      switch (ev.t) {
        case 'peerInfo':
          peer.hostname = ev.hostname ?? '';
          peer.username = ev.username ?? '';
          peer.platform = ev.platform ?? '';
          peer.version = ev.version ?? '';
          peer.terminal_supported = !!ev.terminalSupported;
          peer.displays = (ev.displays ?? []).map((d) => ({
            name: d.name ?? '',
            width: d.width ?? 0,
            height: d.height ?? 0,
            scale: d.scale ?? 1,
          }));
          progress(`Identified ${peer.hostname || 'device'} (${peer.platform || 'unknown platform'})`);
          break;

        case 'state':
          if (ev.state === 'streaming') {
            void startProbe();
          } else if (ev.state === 'error') {
            fail(ev.detail || 'The connection failed.');
          } else if (ev.state === 'closed') {
            // A close before the end marker is a truncated run, not a
            // failure: the handshake facts are still worth keeping.
            finish(opened ? 'The terminal closed before the probe finished.' : 'The connection closed.');
          } else if (ev.state === 'needAccept') {
            progress('Waiting for someone at the device to accept…');
          } else {
            progress(ev.detail || ev.state);
          }
          break;

        case 'loginError':
          fail(ev.message || 'The device rejected the password.');
          break;

        case 'terminalOpened':
          if (!ev.success) {
            finish(ev.message || 'The device would not open a terminal.');
            break;
          }
          terminalId = ev.terminalId;
          opened = true;
          void sendScript();
          break;

        case 'terminalData':
          capture += decoder.decode(ev.data, { stream: true });
          if (probe && capture.includes(probe.end)) {
            finish('');
          } else if (capture.length > MAX_CAPTURE) {
            finish('The device produced more output than the probe allows.');
          }
          break;

        case 'terminalClosed':
          finish(probe && capture.includes(probe.end) ? '' : 'The shell exited before the probe finished.');
          break;

        case 'terminalError':
          finish(ev.message || 'The terminal reported an error.');
          break;
      }
    };

    progress('Connecting…');
    worker.postMessage({
      c: 'connectTerminal',
      config: intelSessionConfig(cfg!, opts.peerId, opts.password ?? '', opts.savedHash),
    } satisfies UiCommand);

    // Fetching the probe needs the platform, which only arrives with the
    // handshake, so this cannot happen before the session is up.
    async function startProbe(): Promise<void> {
      if (probeStarted > 0 || settled) return;
      progress('Connected. Preparing the probe…');

      if (!peer.terminal_supported) {
        finish('This device does not offer terminal access, so only handshake facts were collected.');
        return;
      }
      try {
        probe = await opts.fetchProbe(peer.platform);
      } catch (err) {
        finish(`Could not fetch a probe: ${(err as Error).message}`);
        return;
      }
      if (settled) return;
      if (!probe.supported) {
        finish(`There is no probe for ${peer.platform || 'this platform'}, so only handshake facts were collected.`);
        return;
      }

      probeStarted = Date.now();
      arm(PROBE_TIMEOUT_MS, () => finish('The probe did not finish in time.'));
      worker.postMessage({ c: 'terminalOpen', terminalId: 0, rows: 40, cols: 200 } satisfies UiCommand);
    }

    // Type the script in. Lines go one at a time with a short gap: a terminal
    // in canonical mode has a finite input buffer, and the far end is a real
    // tty, not a pipe that will absorb an arbitrary burst.
    //
    // The prelude goes first, more slowly. It replaces the login shell and
    // silences its echo, and neither can be done while the next line is
    // already on its way; see posixPrelude in internal/intel.
    async function sendScript(): Promise<void> {
      if (!probe) return;

      if (probe.prelude?.length) {
        progress('Preparing the shell…');
        for (const line of probe.prelude) {
          if (settled) return;
          type(line);
          await sleep(PRELUDE_DELAY_MS);
        }
      }

      progress('Collecting…');
      await sleep(SETTLE_MS);
      for (const line of probe.lines) {
        if (settled) return;
        type(line);
        await sleep(LINE_DELAY_MS);
      }
    }

    // Carriage return, not newline. Enter on a real keyboard sends CR, which is
    // what xterm.js sends from the terminal page and what the far end is
    // waiting for. A Unix tty maps it to NL itself (ICRNL), but the Windows
    // console does not treat LF as "run this": it inserts a line break and
    // drops to its `>>` continuation prompt, so the script accumulates
    // forever and never executes.
    function type(line: string): void {
      const bytes = utf8.encode(line + '\r');
      worker.postMessage(
        { c: 'terminalData', terminalId, data: bytes } satisfies UiCommand,
        [bytes.buffer],
      );
    }
  });
}

/** The text between the markers, exclusive. */
function sliceBetween(haystack: string, begin: string, end: string): string {
  const from = haystack.indexOf(begin);
  if (from < 0) return '';
  const start = from + begin.length;
  const to = haystack.indexOf(end, start);
  return to < 0 ? haystack.slice(start) : haystack.slice(start, to);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Build the session config for a collection.
 *
 * Terminal connection type: it negotiates no video at all, so collecting never
 * requests the remote screen. An empty password is legitimate — the device
 * then raises its accept prompt — so it is passed through rather than treated
 * as a missing value.
 */
export function intelSessionConfig(
  cfg: RdGlobalConfig,
  peerId: string,
  password: string,
  savedHash?: string,
) {
  return savedHash
    ? buildSessionConfig(cfg, peerId, '', savedHash, 'terminal')
    : buildSessionConfig(cfg, peerId, password, undefined, 'terminal');
}

// The page is a classic script and loads this module dynamically, so the entry
// point is a global rather than an import.
(globalThis as { __RDGUI_INTEL__?: unknown }).__RDGUI_INTEL__ = { collect };
