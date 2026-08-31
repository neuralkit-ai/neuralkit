import { defineConfig } from 'vite'
import phazeCompile from '@madenowhere/phaze-compile/vite'
import tailwindcss from '@tailwindcss/vite'

// Vite 8 (Rolldown + oxc). Config copied from phaze-cloudflare's own
// `plugin.ts` — the `esbuild` key is deprecated on 8, and oxc wants the
// nested JsxOptions shape rather than esbuild's flat strings.
export default defineConfig({
  // StepIndicator.phaze is a verbatim copy of neuralkit-web's, and its layout IS
  // Tailwind utilities (`relative` + `absolute left-0 top-0` positioning every dot).
  // Without the plugin those classes generate nothing and every span collapses to
  // width 0 in the same spot — measured, not assumed.
  plugins: [phazeCompile(), tailwindcss()],
  oxc: {
    jsx: { runtime: 'automatic', importSource: '@madenowhere/phaze' },
    include: /\.(m?ts|[jt]sx|phaze)$/,
  },
  // Workspace-link contract: excluded from pre-bundling + the roots allowed,
  // or the dev server 404s the symlinked packages.
  optimizeDeps: { exclude: ['@madenowhere/phaze', '@madenowhere/photon'] },
  server: { fs: { allow: ['/Users/r/Minilab/phaze', '/Users/r/Minilab/photon', '.'] } },
  // The polyfill is off because the page ships as ONE inlined module with no
  // imports — there is nothing to preload, and `with_html` gives it no base URL
  // to preload from.
  build: { assetsDir: '.', target: 'safari18', modulePreload: { polyfill: false } },
})
