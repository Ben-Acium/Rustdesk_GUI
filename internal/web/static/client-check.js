// Explains the one failure the bundled client cannot warn about itself.
//
// Over plain HTTP there is no WebCodecs VideoDecoder (it is secure-context
// gated), so the client advertises H.264 only and plays it through Media Source
// Extensions. Chrome *can* play H.264 that way, so the client's own check
// passes and it connects happily — but RustDesk has no software H.264 encoder,
// only a hardware one. A device without a usable hardware encoder therefore
// sends VP9, which this origin cannot decode: input works, screen stays black.
(() => {
  "use strict";
  if (typeof VideoDecoder !== "undefined") return; // full codec support, nothing to say

  const note = document.createElement("div");
  note.className = "rd-codec-warn";
  note.setAttribute("role", "alert");
  note.innerHTML =
    '<strong>Video may stay black on this address.</strong> ' +
    'Served over plain HTTP, the browser can only display <b>H.264</b>, and RustDesk ' +
    'can only produce H.264 from a <i>hardware</i> encoder — many machines, especially ' +
    'virtual ones, have none and will send VP9 instead. Input and clipboard still work. ' +
    '<br>To get a picture, open this page from a secure context: serve it over HTTPS, ' +
    'or add this origin under <code>chrome://flags/#unsafely-treat-insecure-origin-as-secure</code>. ' +
    'That restores VP8/VP9/AV1 decoding.';

  const mount = () => (document.body || document.documentElement).prepend(note);
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount, { once: true });
  } else {
    mount();
  }
})();
