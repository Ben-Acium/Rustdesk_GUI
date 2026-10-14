// rustdeskgui: a real terminal for the terminal-only page.
//
// The transport is already a PTY. The worker reports raw bytes on
// `terminalData` and accepts `terminalResize` with rows and cols, so escape
// sequences, colour, cursor addressing and alternate-screen programs all
// arrive intact. Upstream's TerminalPanel throws that away: it runs the stream
// through a control-sequence stripper and renders the leftovers into a <pre>,
// driven by a single-line command input.
//
//   case 'terminalData':
//     this.appendText(this.controlStripper.push(
//       this.decoder.decode(this.byteNormalizer.push(event.data), { stream: true }),
//     ));
//
// That is a UI decision, not a protocol limit. This panel speaks the same
// worker protocol and hands the bytes to xterm.js instead, which is what makes
// vim, htop, less, tab completion and Ctrl-C behave as they would in any other
// terminal.
//
// It is deliberately a sibling of TerminalPanel rather than a patch of it:
// upstream keeps its panel for the in-session dock, and this one only ever
// serves our standalone page.
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import type { SessionConfig, SessionEvent, UiCommand } from '../core/contracts';
import { disconnectIndependentWorker } from './advanced-worker-lifecycle';

const utf8 = new TextEncoder();

type Deps = {
  root: HTMLElement;
  workerUrl: string;
  getConfig(): SessionConfig | null;
  toast(message: string): void;
};

export class RdGuiTerminalPanel {
  private worker: Worker | undefined;
  private term: Terminal | undefined;
  private fit: FitAddon | undefined;
  private status: HTMLElement | undefined;
  private terminalId = 0;
  private opened = false;
  private resizeObserver: ResizeObserver | undefined;

  constructor(private readonly deps: Deps) {}

  open(): void {
    if (this.term) {
      this.term.focus();
      return;
    }

    const shell = document.createElement('div');
    shell.className = 'rdgui-term';
    shell.innerHTML = `
      <p class="rdgui-term-status" role="status">Connecting…</p>
      <div class="rdgui-term-screen"></div>`;
    this.deps.root.appendChild(shell);
    this.status = shell.querySelector<HTMLElement>('.rdgui-term-status')!;
    const screen = shell.querySelector<HTMLElement>('.rdgui-term-screen')!;

    this.term = new Terminal({
      convertEol: false,
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
      scrollback: 10000,
      // Match the page rather than xterm's default black, so the terminal
      // looks like part of this console instead of a window pasted onto it.
      theme: { background: '#0b0e14', foreground: '#e7ebf3', cursor: '#e7ebf3' },
    });
    this.fit = new FitAddon();
    this.term.loadAddon(this.fit);
    this.term.open(screen);
    this.fit.fit();

    // Keystrokes. onData carries the usual escape sequences for arrows and
    // Ctrl-chords, so nothing here needs a key table of its own; onBinary
    // carries the 8-bit case xterm reports separately.
    this.term.onData((data) => this.send(utf8.encode(data)));
    this.term.onBinary((data) => {
      const bytes = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i) & 0xff;
      this.send(bytes);
    });

    if (typeof ResizeObserver !== 'undefined') {
      this.resizeObserver = new ResizeObserver(() => this.resize());
      this.resizeObserver.observe(screen);
    }
    window.addEventListener('resize', this.onWindowResize);

    this.connect();
  }

  private onWindowResize = (): void => this.resize();

  private connect(): void {
    if (this.worker) return;
    const config = this.deps.getConfig();
    if (!config) {
      this.fail('No connection details for this device');
      return;
    }
    this.worker = new Worker(this.deps.workerUrl, { type: 'module' });
    this.worker.onmessage = (event: MessageEvent<SessionEvent>) => this.onEvent(event.data);
    this.worker.onerror = () => this.fail('Terminal worker failed');
    this.worker.postMessage({
      c: 'connectTerminal',
      config: { ...config, connType: 'terminal' },
    } satisfies UiCommand);
  }

  private onEvent(event: SessionEvent): void {
    switch (event.t) {
      case 'state':
        if (event.state === 'streaming') {
          this.setStatus('Opening terminal…');
          this.worker?.postMessage({
            c: 'terminalOpen',
            terminalId: 0,
            rows: this.term?.rows ?? 24,
            cols: this.term?.cols ?? 80,
          } satisfies UiCommand);
        } else if (event.state === 'error' || event.state === 'closed') {
          this.fail(event.detail || (event.state === 'closed' ? 'Terminal disconnected' : 'Terminal connection failed'));
        } else {
          this.setStatus(event.detail || event.state);
        }
        break;
      case 'loginError':
        this.fail(event.message);
        break;
      case 'terminalOpened':
        if (!event.success) {
          this.fail(event.message || 'The remote terminal could not be opened');
          break;
        }
        this.terminalId = event.terminalId;
        this.opened = true;
        this.setStatus('');
        this.resize(); // the shell starts at 24x80 until told otherwise
        this.term?.focus();
        break;
      case 'terminalData':
        // Raw bytes, straight through. xterm decodes UTF-8 across chunk
        // boundaries itself, so no decoder is needed on this side.
        this.term?.write(event.data);
        break;
      case 'terminalClosed':
        this.opened = false;
        this.setStatus(`Terminal exited with code ${event.exitCode}`);
        break;
      case 'terminalError':
        this.fail(event.message);
        break;
    }
  }

  private send(data: Uint8Array): void {
    if (!this.opened || data.length === 0) return;
    this.worker?.postMessage(
      { c: 'terminalData', terminalId: this.terminalId, data } satisfies UiCommand,
      [data.buffer],
    );
  }

  private resize(): void {
    if (!this.fit || !this.term) return;
    const before = { rows: this.term.rows, cols: this.term.cols };
    this.fit.fit();
    if (!this.opened) return;
    if (this.term.rows === before.rows && this.term.cols === before.cols) return;
    this.worker?.postMessage({
      c: 'terminalResize',
      terminalId: this.terminalId,
      rows: this.term.rows,
      cols: this.term.cols,
    } satisfies UiCommand);
  }

  private setStatus(message: string): void {
    if (!this.status) return;
    this.status.textContent = message;
    this.status.hidden = message === '';
  }

  private fail(message: string): void {
    this.opened = false;
    this.setStatus(message);
    this.deps.toast(message);
    this.stopWorker(false);
  }

  private stopWorker(closeTerminal: boolean): void {
    const worker = this.worker;
    this.worker = undefined;
    if (!worker) return;
    if (closeTerminal && this.opened) {
      worker.postMessage({ c: 'terminalClose', terminalId: this.terminalId } satisfies UiCommand);
    }
    disconnectIndependentWorker(worker);
  }

  destroy(): void {
    this.stopWorker(true);
    this.resizeObserver?.disconnect();
    this.resizeObserver = undefined;
    window.removeEventListener('resize', this.onWindowResize);
    this.term?.dispose();
    this.term = undefined;
    this.fit = undefined;
    this.opened = false;
  }
}
