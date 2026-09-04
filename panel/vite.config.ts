import { defineConfig } from 'vite'
import native from '@madenowhere/phaze-native/vite'
import tailwindcss from '@tailwindcss/vite'
import glsl from 'vite-plugin-glsl'
import { sizeReport } from '@madenowhere/vite-plugin-phaze'

// THE UI COMPONENT IS NOT COPIED HERE. `@web/` points at neuralkit-web's `src/`,
// so StepIndicator.phaze has exactly ONE definition and cannot drift — a copy
// nearly shipped a broken panel already, when the web-side prop contract changed
// to `data`-loaded steps while this app still passed a signal.
const WEB = new URL('../../neuralkit-web/src/', import.meta.url).pathname

export default defineConfig({
  plugins: [
    // The native target. Generates `src/pages/**` at build (the page runs against
    // linkedom, so its copy is in the HTML) and hydrates it in the webview.
    // `publish: true` folds the entry module, the stylesheet and every dynamic
    // import into ONE document — `dist/index.html` is the whole build, which is
    // what `with_html` needs (no base URL, so nothing may be left as a src/href)
    // and what `include_str!` embeds. Bundles phaze-compile and the oxc JSX
    // config, so neither is listed here.
    native({ shell: 'wry', publish: true }),
    // StepIndicator.phaze's layout IS Tailwind utilities (`relative` + `absolute
    // left-0 top-0` positioning every dot). Without the plugin those classes generate
    // nothing and every span collapses to width 0 in the same spot — measured, not
    // assumed. `src/styles.css` carries the `@source` that makes Tailwind scan the
    // out-of-tree file — required, and verified against a COLD build.
    tailwindcss(),
    // `glsl` resolves fabric's WGSL `#include` graph (sdf.wgsl pulls in 36 primitives/materials)
    // and compresses it. `warnDuplicatedImports: false` because fabric deliberately includes each
    // material from both the fs and fs_fast pipelines — same flags neuralkit-web uses.
    // @ts-ignore — same as neuralkit-web: the plugin's published types omit these options.
    glsl({ compress: true, warnDuplicatedImports: false }),
    // Same grouped, labelled build report neuralkit-web prints. Under `publish`
    // there is ONE chunk — every fabric `import()` site is folded into it — so the
    // report is the size of the script the document carries, before inlining.
    sizeReport({
      groups: [
        { name: 'panel',    match: (c) => c.moduleIds.some((m) => m.includes('/panel/src/')) },
        { name: 'graviton', match: (c) => c.moduleIds.some((m) => m.includes('/graviton/')) },
        { name: 'fabric',   match: (c) => c.moduleIds.some((m) => m.includes('/fabric/') || m.includes('/wgsl/')) },
      ],
    }),
  ],
  resolve: {
    alias: [{ find: /^@web\//, replacement: WEB }],
    // Both projects `link:` phaze and photon to the SAME realpath, so importing
    // across the boundary does not fork the runtime. Stated explicitly because a
    // second copy would not error — it would just break reactivity.
    dedupe: ['@madenowhere/phaze', '@madenowhere/photon', '@madenowhere/graviton'],
  },
  // Workspace-link contract: excluded from pre-bundling + the roots allowed,
  // or the dev server 404s the symlinked packages.
  optimizeDeps: { exclude: ['@madenowhere/phaze', '@madenowhere/phaze-native', '@madenowhere/photon', '@madenowhere/graviton'] },
  server: { fs: { allow: ['/Users/r/Minilab/phaze', '/Users/r/Minilab/photon', '/Users/r/Minilab/graviton', WEB, '.'] } },
})
