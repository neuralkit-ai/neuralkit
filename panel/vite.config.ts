import { defineConfig } from 'vite'
import native from '@madenowhere/phaze-native/vite'
import { phazeChunks } from '@madenowhere/phaze-vite/chunks'
import tailwindcss from '@tailwindcss/vite'
import glsl from 'vite-plugin-glsl'
import { fabricShakePlugin } from '../../neuralkit-web/build/vite-plugin-fabric-shake.mjs'
import { sizeReport } from '@madenowhere/vite-plugin-phaze'

// THE UI COMPONENT IS NOT COPIED HERE. `@web/` points at neuralkit-web's `src/`,
// so StepIndicator.phaze has exactly ONE definition and cannot drift — a copy
// nearly shipped a broken panel already, when the web-side prop contract changed
// to `data`-loaded steps while this app still passed a signal.
const WEB = new URL('../../neuralkit-web/src/', import.meta.url).pathname

// The chunk layout is the CONSUMER's, exactly as in neuralkit-web's config: the
// plugin's built-in rules stay off and `phazeChunks()` is called here for the
// runtime split, with this app's own libraries layered on top. Same flag set
// as -web (fold directives / actions / subpaths / components into consumers;
// the sub-3 KB `phaze` runtime always stays its own chunk, so its size stays
// measurable).
const phazeChunkingRules = phazeChunks({ chunkDirectives: false, chunkActions: false, chunkSubpaths: false, chunkComponents: false })

export default defineConfig({
  plugins: [
    // The native target. Generates `src/pages/**` at build (the page runs against
    // linkedom, so its copy is in the HTML) and hydrates it in the webview over
    // `nk://` — `dist/index.html` references the entry as a file, and fabric's lazy
    // chunks are served out of the same embedded directory. No `publish`: the
    // string-loaded document it adds has a null origin, and this card needs WebGPU.
    // Bundles phaze-compile and the oxc JSX config, so neither is listed here.
    // `compress`: the served scripts and stylesheet are written as `*.gz` (or `*.br`);
    // panel.rs's protocol handler decodes by suffix — gzip with the flate2 the tray
    // already links, brotli only under `cargo --features panel-brotli`. WebKit does not
    // decode a scheme-handler body itself (measured: `Content-Encoding: br` reached the
    // parser as raw bytes), so the decode is the shell's, not a header's.
    // Measured on this asset set (2026-09-04): brotli packs 50.3 → 44.7 kB, but its decoder
    // adds 165 kB to the binary (7,547,664 → 7,712,848) and decodes slower (entry 218 →
    // 380 µs). gzip until the assets are ~30× larger — the decoder is a fixed cost, the
    // tighter packing scales with the assets.
    native({ shell: 'wry', compress: 'gzip' }),
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
    // Fabric's shaker, as in neuralkit-web's config: the transform-stage region
    // strips (RIG / GLASS / MESH features) that keep the shader correct, plus the
    // COND_FEATURE strips — fabric's `import()` sites behind runtime conditions
    // (`stats`, `showAxes`, `geometryUrl`, background mips) are removed when this
    // app's source never turns the condition on, so the bundler never emits the
    // chunk and the binary never embeds it. Detection is an fs-walk of `src/`
    // (the cwd's, i.e. this panel's). `regionsOnly` as in -web.
    fabricShakePlugin({ regionsOnly: true }),
    // Same grouped, labelled build report neuralkit-web prints. Under `publish`
    // there is ONE chunk — every fabric `import()` site is folded into it — so the
    // report is the size of the script the document carries, before inlining.
    sizeReport({
      // The same map and the same groups neuralkit-web's config declares. The
      // map: fabric's own runtime conditions, identical wherever fabric is
      // consumed — a chunk listed here loads only when its condition holds
      // (`◌ conditional`); a code-split chunk that is not listed hydrates
      // SSR-painted content (`◐ hydrates`).
      conditionalReasons: {
        StatsHUD:     'scene.stats === true',
        sdfEngine:    'first SDF shape mount',
        sdf:          'sdfEngine loads its shader',
        textEngine:   'first <Text> mount',
        text:         'textEngine loads its shader',
        grid:         'Grid mounts (its WGSL shader)',
        loadGeometry: 'Grid has geometryUrl (PLY)',
        meshEngine:   'first <Mesh> mount',
        axes:         'scene.showAxes === true',
        bgmip:        'glass material with roughness > 0',
        blit:         'drag-resize triggers offscreen blit',
      },
      // The groups, as -web orders them: pages, phaze-owned chunks, this app's
      // components (the fabric wrapper lands HERE, as FabricCanvas does in -web,
      // so `components` must precede `fabric`), graviton, then fabric's own lazy
      // engine chunks.
      groups: [
        { name: 'pages',      match: (c) => !c.chunkName.startsWith('phaze') && c.moduleIds.some((m) => m.includes('/src/pages/')) },
        { name: 'phaze',      match: (c) => c.chunkName === 'phaze' || c.chunkName.startsWith('phaze-')
                                || ['store', 'portal', 'catch', 'time', 'match', 'list', 'defer', 'revalidate'].includes(c.chunkName) },
        { name: 'components', match: (c) => c.moduleIds.some((m) => m.includes('/src/components/') || /\/panel\/src\/FabricCube\.tsx$/.test(m)) },
        { name: 'graviton',   match: (c) => c.moduleIds.some((m) => m.includes('/graviton/')) },
        { name: 'fabric',     match: (c) => c.moduleIds.some((m) => m.includes('/fabric/') || m.includes('/wgsl/')) },
      ],
    }),
  ],
  build: {
    rolldownOptions: {
      output: {
        // -web's layout, on this app's names. `minSize: 0` so rolldown never
        // merges a small chunk into a consumer (how the runtime once collapsed
        // out of its own chunk); the explicit `test` + priority claims the
        // shared runtime before the name function runs.
        codeSplitting: {
          minSize: 0,
          groups: [{
            name: 'phaze',
            test: (id: string) => phazeChunkingRules(id) === 'phaze',
            priority: 100,
          }, {
            name(id: string) {
              // Remaining phaze-owned chunks (the router, opt-in subpaths), then this app.
              const phazeChunk = phazeChunkingRules(id)
              if (phazeChunk && phazeChunk !== 'phaze') return phazeChunk
              // The fabric wrapper → 'fabric-cube'; fabric's statically imported
              // engine follows transitively, its `import()` targets stay their own
              // async chunks (named here they would join the eager chunk).
              if (/\/panel\/src\/FabricCube\.tsx$/.test(id)) return 'fabric-cube'
              // Graviton — one chunk for the whole package.
              if (id.includes('/graviton/')) return 'graviton'
              // Photon and the shared -web components → ui-components, as in -web.
              if (id.includes('/photon/')) return 'ui-components'
              if (id.includes('/src/components/')) return 'ui-components'
              return null
            },
          }],
        },
      },
    },
  },
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
