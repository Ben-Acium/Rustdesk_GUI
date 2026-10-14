// Builds rustdeskgui's extra entry point into the same output tree as the
// upstream bundle, mirroring the options esbuild.mjs uses.
//
// Kept separate rather than patched into esbuild.mjs so the upstream build
// file stays untouched and a version bump cannot silently drop our entry.
import { build } from 'esbuild';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));
const outdir = resolve(__dirname, '../public/rdclient');

await build({
  entryPoints: {
    'rdgui-standalone': resolve(__dirname, 'src/ui/rdgui-standalone.ts'),
    // Intel's collector. Its own entry point rather than part of the
    // standalone bundle: the device page needs the session machinery but none
    // of the file panel, the terminal or their stylesheets.
    'rdgui-intel': resolve(__dirname, 'src/ui/rdgui-intel.ts'),
  },
  outdir,
  bundle: true,
  format: 'esm',
  target: ['chrome110', 'edge110'],
  platform: 'browser',
  sourcemap: false,
  minify: true,
  legalComments: 'linked',
  logLevel: 'info',
  loader: { '.wasm': 'binary', '.css': 'css' },
  alias: {
    // Same two aliases the upstream build needs; see its esbuild.mjs.
    'libsodium-wrappers': require.resolve('libsodium-wrappers'),
    stream: resolve(__dirname, 'src/shims/node-stream.ts'),
  },
  define: { 'process.env.NODE_ENV': '"production"' },
});
console.log(`[rustdeskgui] built rdgui-standalone -> ${outdir}`);
