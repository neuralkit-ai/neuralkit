import { defineConfig } from 'vite'
import phazeCompile from '@madenowhere/phaze-compile/vite'
import tailwindcss from '@tailwindcss/vite'
import glsl from 'vite-plugin-glsl'

// Vite 8 (Rolldown + oxc). Config copied from phaze-cloudflare's own
// `plugin.ts` — the `esbuild` key is deprecated on 8, and oxc wants the
// nested JsxOptions shape rather than esbuild's flat strings.
// THE UI COMPONENT IS NOT COPIED HERE. `@web/` points at neuralkit-web's `src/`,
// so StepIndicator.phaze has exactly ONE definition and cannot drift — a copy
// nearly shipped a broken panel already, when the web-side prop contract changed
// to `data`-loaded steps while this app still passed a signal.
const WEB = new URL('../../neuralkit-web/src/', import.meta.url).pathname

export default defineConfig({
  // StepIndicator.phaze's layout IS Tailwind utilities (`relative` + `absolute
  // left-0 top-0` positioning every dot). Without the plugin those classes generate
  // nothing and every span collapses to width 0 in the same spot — measured, not
  // assumed. `src/styles.css` carries the `@source` that makes Tailwind scan the
  // out-of-tree file — required, and verified against a COLD build.
  // `glsl` resolves fabric's WGSL `#include` graph (sdf.wgsl pulls in 36 primitives/materials)
  // and compresses it. `warnDuplicatedImports: false` because fabric deliberately includes each
  // material from both the fs and fs_fast pipelines — same flags neuralkit-web uses.
  plugins: [
    phazeCompile(),
    tailwindcss(),
    // @ts-ignore — same as neuralkit-web: the plugin's published types omit these options.
    glsl({ compress: true, warnDuplicatedImports: false }),
  ],
  resolve: {
    alias: [{ find: /^@web\//, replacement: WEB }],
    // Both projects `link:` phaze and photon to the SAME realpath, so importing
    // across the boundary does not fork the runtime. Stated explicitly because a
    // second copy would not error — it would just break reactivity.
    dedupe: ['@madenowhere/phaze', '@madenowhere/photon', '@madenowhere/graviton'],
  },
  oxc: {
    jsx: { runtime: 'automatic', importSource: '@madenowhere/phaze' },
    include: /\.(m?ts|[jt]sx|phaze)$/,
  },
  // Workspace-link contract: excluded from pre-bundling + the roots allowed,
  // or the dev server 404s the symlinked packages.
  optimizeDeps: { exclude: ['@madenowhere/phaze', '@madenowhere/photon', '@madenowhere/graviton'] },
  server: { fs: { allow: ['/Users/r/Minilab/phaze', '/Users/r/Minilab/photon', '/Users/r/Minilab/graviton', WEB, '.'] } },
  // The polyfill is off because the page ships as ONE inlined module with no
  // imports — there is nothing to preload, and `with_html` gives it no base URL
  // to preload from.
  build: { assetsDir: '.', target: 'safari18', modulePreload: { polyfill: false } },
})
