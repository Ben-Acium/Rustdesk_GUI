// rustdeskgui: a files-only / terminal-only entry point for the CortenDesk
// web client.
//
// The bundled UI reaches its file manager and terminal only from inside a live
// desktop session:
//
//   getConfig: () => {
//     if (!this.cfg || this.state !== 'streaming') return null;
//     return buildSessionConfig(this.cfg, this.peerId, '', this.sessionHashHex, 'fileTransfer');
//   }
//
// That gate exists so the panel can reuse the desktop login's h1 credential
// and avoid a second password prompt - not because the protocol requires a
// desktop. ConnType.FILE_TRANSFER and ConnType.TERMINAL are first-class
// connection types that negotiate no video at all, and buildSessionConfig
// accepts a plaintext password directly. Asking for the password once here
// buys a session that never sees the remote screen.
//
// This file is added to the upstream tree at image build time, alongside
// rdgui-terminal.ts. It depends on FilePanel, buildSessionConfig and the saved
// credential helpers, so an upstream change to any of those fails the Docker
// build rather than breaking silently at runtime.
//
// The terminal is ours rather than upstream's TerminalPanel; see
// rdgui-terminal.ts for why.
import './app.css';
import { FilePanel } from './file-panel';
import { RdGuiTerminalPanel } from './rdgui-terminal';
import {
  buildSessionConfig,
  clearSavedHash,
  loadSavedHash,
  peerIdFromSearch,
  resolveWorkerUrl,
  saveSavedHash,
  type RdGlobalConfig,
} from './common';
import type { SessionConfig } from '../core/contracts';

type Mode = 'files' | 'terminal';

const cfg = (globalThis as { __RD__?: RdGlobalConfig }).__RD__;
const root = document.getElementById('rd-standalone');

function fail(message: string): never {
  if (root) {
    root.innerHTML = `<p class="rdgui-error" role="alert">${message}</p>`;
  }
  throw new Error(message);
}

if (!cfg) fail('Client configuration is missing.');
if (!root) fail('Page is missing its #rd-standalone mount point.');

// The mode comes from the path (/files, /terminal) so the URLs stay readable;
// ?mode= is accepted as a fallback.
const mode: Mode =
  location.pathname.replace(/\/+$/, '').endsWith('/terminal') ||
  new URLSearchParams(location.search).get('mode') === 'terminal'
    ? 'terminal'
    : 'files';
const peerId = peerIdFromSearch(location.search) ?? cfg.peerId ?? '';
if (!peerId) fail('No device id in the URL.');

const workerUrl = resolveWorkerUrl(cfg.workerUrl, null, import.meta.url);

// The password is held only for as long as the panel may reconnect; getConfig
// is called again on every (re)connect, so it cannot be cleared after first use.
let password = '';

// A saved credential is h1 = SHA256(password||salt), not a password. It reaches
// localStorage from the server before this module loads (see
// static/rdclient-compat.js) and goes back the same way, so saving here needs
// no API call of its own.
//
// ?ask=1 is how the resume screen's "use a different password" link gets back
// to the form when a stored credential has gone stale.
const askForPassword = new URLSearchParams(location.search).get('ask') === '1';
let savedHash: string | undefined =
  askForPassword ? undefined : (loadSavedHash(peerId) ?? undefined);

function toast(message: string): void {
  const el = document.getElementById('rdgui-toast');
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
  window.setTimeout(() => { el.hidden = true; }, 4000);
}

function sessionConfig(connType: SessionConfig['connType']): SessionConfig | null {
  // An empty password is a legitimate choice, not an unready state: the device
  // then raises its accept prompt and someone approves the session by hand.
  // Returning null here would have made the page's own offer of that
  // impossible, because the panel reads null as "not connected yet".
  if (savedHash) return buildSessionConfig(cfg!, peerId, '', savedHash, connType);
  return buildSessionConfig(cfg!, peerId, password, undefined, connType);
}

// Double-clicking a folder row does not open it.
//
// The panel delegates both events to the table body and resolves the row with
// `(e.target).closest('tr[data-idx]')`. Its click handler re-renders the list
// through `innerHTML = rows.join('')`, so the first click of a double-click
// destroys the element the second one lands on. Because the two clicks then
// hit different nodes, the browser does not retarget the dblclick - it never
// dispatches one at all, which was confirmed against headless Chromium:
//
//   click detail=1 target=TD row=yes
//   click detail=2 target=TD row=yes
//   (no dblclick)
//
// The second click is still a valid hook: it carries detail === 2 and its
// target is a live row. So synthesize the dblclick the panel is waiting for.
//
// Two details matter. The dispatch is deferred a tick and skipped if a real
// dblclick turns up, so this disappears by itself should upstream ever render
// in place. And the row is resolved again at dispatch time, because the one
// seen during capture has been replaced by the re-render that follows.
function repairRowDoubleClick(): void {
  let nativeSeen = false;
  document.addEventListener('dblclick', () => { nativeSeen = true; }, true);

  document.addEventListener(
    'click',
    (e) => {
      const ev = e as MouseEvent;
      if (ev.detail !== 2) return;
      const target = ev.target as HTMLElement | null;
      if (!target?.closest('tr[data-idx]')) return;

      nativeSeen = false;
      const { clientX, clientY } = ev;
      setTimeout(() => {
        if (nativeSeen) return; // a real dblclick arrived; stand down
        const under = document.elementFromPoint(clientX, clientY) as HTMLElement | null;
        const row = under?.closest('tr[data-idx]');
        if (!row) return;
        row.dispatchEvent(new MouseEvent('dblclick', {
          bubbles: true, cancelable: true, view: window, clientX, clientY,
        }));
      }, 0);
    },
    true,
  );
}

function start(): void {
  const stage = document.getElementById('rdgui-stage');
  if (stage) stage.hidden = false;
  for (const id of ['rdgui-login', 'rdgui-resume']) {
    const el = document.getElementById(id);
    if (el) el.hidden = true;
  }

  if (mode === 'terminal') {
    new RdGuiTerminalPanel({
      root: root!,
      workerUrl,
      toast,
      getConfig: () => sessionConfig('terminal'),
    }).open();
    return;
  }

  repairRowDoubleClick();

  // FilePanel fills the element it is handed, so give it the whole stage.
  new FilePanel({
    viewport: root!,
    workerUrl,
    toast,
    getConfig: () => sessionConfig('fileTransfer'),
  }).open();
}

const form = document.getElementById('rdgui-login') as HTMLFormElement | null;
const input = document.getElementById('rdgui-password') as HTMLInputElement | null;
const remember = document.getElementById('rdgui-remember') as HTMLInputElement | null;
const resume = document.getElementById('rdgui-resume');

if (!form || !input) fail('Page is missing its password form.');

// Take the credential the session computes, but only once it has been
// accepted. The hook that provides it lives in static/rdclient-compat.js and
// releases a value only after the session reaches 'streaming', so a password
// the device rejected is never stored. Writing it to localStorage is what
// sends it to the server; the mirror in that same script does the rest.
type CredentialHook = { onCredential(cb: (hash: string) => void): void };
const hook = (globalThis as { __RDGUI__?: CredentialHook }).__RDGUI__;
hook?.onCredential((hash) => {
  if (!remember?.checked) return;
  saveSavedHash(peerId, hash);
});

// A stored credential means there is nothing to ask for. Show what is
// happening and why, with a way back to the form if it has gone stale.
if (savedHash) {
  form.hidden = true;
  if (resume) resume.hidden = false;
  start();
} else {
  // Arriving via "use a different password" means the stored one is wrong.
  // Drop it now rather than leaving it to shadow whatever is typed next.
  if (askForPassword) clearSavedHash(peerId);

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    // An empty password is legitimate: the device then opens its accept prompt
    // and someone approves the session by hand.
    password = input.value;
    input.value = '';
    start();
  });

  input.focus();
}
