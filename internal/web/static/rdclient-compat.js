// Corrections applied to the bundled client from outside it. Loaded as a
// classic script before the module bundle, so it runs first.
(() => {
  "use strict";

  const BRAND = "Rust Control Center";

  // --- 1. Restore the icon fallback. ------------------------------------
  //
  // The client picks between a Remix Icon webfont glyph and its own inline SVG:
  //
  //   if (ic.ri && hasRemixIcons()) return `<i class="${ic.ri}"></i>`;
  //   return '<svg ...>' + ic.svg + '</svg>';
  //
  // and detects the font with `document.fonts.check('16px remixicon')`. That
  // call returns true for a family that does not exist at all — verified in
  // Chromium, where '16px DefinitelyNotInstalledXYZ' also reports true. The
  // font ships with the upstream Laravel console, not with the bundle, so the
  // client emits <i class="ri-..."> against a font nobody loaded and the
  // toolbar buttons render blank.
  //
  // Narrow the false positive to that one family and their own SVG path takes
  // over. Every icon defines an svg, so nothing is lost.
  try {
    const fonts = document.fonts;
    if (fonts && typeof fonts.check === "function") {
      const check = fonts.check.bind(fonts);
      fonts.check = function (font, text) {
        if (typeof font === "string" && /remixicon/i.test(font)) return false;
        return check(font, text);
      };
    }
  } catch (e) {
    // A browser that will not let us wrap it still renders the font glyphs as
    // blanks; nothing here can make that worse.
  }

  // --- 2. Keep the page title ours. -------------------------------------
  //
  // The client sets `document.title = `${peerId} — CortenDesk`` whenever it
  // connects, replacing the title this server rendered. Put it back.
  try {
    const ours = document.title;
    const titleEl = document.querySelector("title");
    if (titleEl && window.MutationObserver) {
      new MutationObserver(() => {
        if (document.title !== ours) document.title = ours;
      }).observe(titleEl, { childList: true, characterData: true, subtree: true });
    }
  } catch (e) {
    /* cosmetic only */
  }

  // --- 3. Make "save password" follow the account, not the browser. -----
  //
  // The bundle already implements the feature, against localStorage, keyed
  // `cortendesk.rdpw.<peerId>` and holding h1 = SHA256(password||salt) — a
  // per-device credential, never the typed password. This server stores the
  // same value, so it can be shared by every browser that signs in.
  //
  // Two hooks join them, and nothing else changes: the checkbox, the sign
  // straight in on a saved credential and the forget-on-untick are all
  // upstream's, working against storage they already use.
  //
  //   seed    what the server has into localStorage, before the bundle looks
  //   mirror  what the bundle writes back up to the server
  //
  // The server is authoritative. A credential it does not have is cleared
  // locally rather than uploaded, so "forget" on the device list actually
  // forgets rather than being undone by the next page that still held a copy.
  const PW_PREFIX = "cortendesk.rdpw.";
  try {
    const host = document.querySelector("[data-saved-hash]");
    if (host && host.dataset.canSave === "1") {
      const peerId =
        host.dataset.peerId ||
        new URLSearchParams(location.search).get("id") ||
        "";
      if (peerId) {
        const key = PW_PREFIX + peerId;
        const saved = host.dataset.savedHash || "";

        // Seed first, with the hooks not yet installed, so this write is not
        // mistaken for the bundle saving something and echoed back.
        try {
          if (saved) localStorage.setItem(key, saved);
          else localStorage.removeItem(key);
        } catch (e) {
          /* private window or blocked storage: fall back to typing it */
        }

        installCredentialMirror(peerId);
      }
    }
  } catch (e) {
    /* the password box still works; this only saves retyping */
  }

  function installCredentialMirror(peerId) {
    const ls = window.localStorage;
    const key = PW_PREFIX + peerId;
    const setItem = ls.setItem.bind(ls);
    const removeItem = ls.removeItem.bind(ls);

    ls.setItem = function (k, v) {
      setItem(k, v);
      if (k === key) send("PUT", peerId, String(v));
    };
    ls.removeItem = function (k) {
      removeItem(k);
      if (k === key) send("DELETE", peerId, null);
    };
  }

  function send(method, peerId, hash) {
    const url = "/api/devices/" + encodeURIComponent(peerId) + "/secret";
    fetch(url, {
      method: method,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": readCookie("rdgui_csrf"),
      },
      body: hash === null ? undefined : JSON.stringify({ hash: hash }),
    })
      .then((res) => {
        if (!res.ok) {
          console.warn("rustdeskgui: saving the device password failed", res.status);
        }
      })
      .catch((err) => {
        // Non-fatal by design: the session in front of the user is unaffected,
        // and the next connection simply asks for a password again.
        console.warn("rustdeskgui: saving the device password failed", err);
      });
  }

  // Publish a device credential to whatever on this page wants to save it.
  //
  // Only the session worker ever sees h1, and the panels that own a worker do
  // not forward it, so the files-only and terminal-only pages have no other
  // way to offer "remember this password". Wrapping the constructor lets them
  // listen without either side being modified.
  //
  // Timing is the subtle part. The session emits h1 while it computes the
  // login hash — before the device has accepted it — so a wrong password
  // emits one too. Upstream only persists once the session streams; this
  // holds the value per worker and releases it on exactly that signal, so a
  // rejected password is never saved.
  try {
    const waiters = [];
    const NativeWorker = window.Worker;
    if (typeof NativeWorker === "function") {
      const Wrapped = function (url, options) {
        const worker = new NativeWorker(url, options);
        let pending = "";
        worker.addEventListener("message", (event) => {
          const msg = event.data;
          if (!msg || typeof msg !== "object") return;
          if (msg.t === "credentials" && typeof msg.hashHex === "string") {
            pending = msg.hashHex;
          } else if (msg.t === "state" && msg.state === "streaming" && pending) {
            const hash = pending;
            pending = "";
            for (const cb of waiters) {
              try {
                cb(hash);
              } catch (e) {
                /* one bad listener must not break the session */
              }
            }
          }
        });
        return worker;
      };
      Wrapped.prototype = NativeWorker.prototype;
      window.Worker = Wrapped;
    }
    window.__RDGUI__ = window.__RDGUI__ || {};
    window.__RDGUI__.onCredential = function (cb) {
      if (typeof cb === "function") waiters.push(cb);
    };
  } catch (e) {
    // Without this the pages still connect; they just cannot offer to
    // remember the password.
    window.__RDGUI__ = window.__RDGUI__ || {};
    window.__RDGUI__.onCredential = function () {};
  }

  function readCookie(name) {
    const parts = document.cookie.split("; ");
    for (const part of parts) {
      const eq = part.indexOf("=");
      if (eq > 0 && part.slice(0, eq) === name) {
        return decodeURIComponent(part.slice(eq + 1));
      }
    }
    return "";
  }

  // --- 4. One-shot repairs that wait for the bundle to render. ----------
  //
  // Each returns true once it has done its work. They share a single observer
  // over the document, which disconnects as soon as the last one is satisfied
  // so nothing of ours runs during a session.
  const fixups = [
    // Relabel the connect card's logo.
    //
    // The toolbar's mark is alt="", but the card's carries alt="CortenDesk".
    // Both images are ours — /rdclient/logo.png is served by this app, not by
    // the bundle — so only the alternative text is wrong, and only a screen
    // reader or a failed image load would ever surface it. The wordmarks
    // beside them are relabelled in CSS; this is the one string CSS cannot
    // reach.
    function relabelLogo() {
      const imgs = document.querySelectorAll('img[alt="CortenDesk"]');
      imgs.forEach((img) => img.setAttribute("alt", BRAND));
      return imgs.length > 0;
    },

    // Dock the "back to devices" button into the toolbar.
    //
    // It is our element, not the bundle's, so it starts out fixed to the top
    // left of the page — which is also where the brand sits, so it covered our
    // own logo. Moving it into the toolbar's right-hand cell puts it in normal
    // flow beside the avatar, where it can no longer overlap anything and
    // follows the bar when fullscreen slides the chrome away.
    //
    // If the bundle never renders there is no toolbar to dock into, and the
    // button stays where it is — still usable, and with no logo left to cover.
    function dockBackButton() {
      const back = document.querySelector(".rd-back");
      const user = document.querySelector("#rd-toolbar .rd-tb-user");
      if (!back || !user) return false;
      user.closest("#rd-toolbar").classList.add("rd-has-back");
      user.classList.add("rd-has-back");
      user.insertBefore(back, user.firstChild);
      back.classList.add("rd-back--docked");
      return true;
    },
  ];

  try {
    let pending = fixups.filter((fn) => !run(fn));
    if (pending.length && window.MutationObserver) {
      const obs = new MutationObserver(() => {
        pending = pending.filter((fn) => !run(fn));
        if (!pending.length) obs.disconnect();
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
      // Never leave it running: whatever has not appeared by now is not coming.
      setTimeout(() => obs.disconnect(), 30000);
    }
  } catch (e) {
    /* cosmetic only */
  }

  // A fixup that throws is treated as finished, so one broken repair cannot
  // keep the observer alive for the whole session.
  function run(fn) {
    try {
      return fn();
    } catch (e) {
      return true;
    }
  }
})();
