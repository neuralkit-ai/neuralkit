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
    // The native target. Renders the `artifact: true` views of `src/views/**` at build
    // (the view runs against linkedom, so its copy is in the HTML) and hydrates it in the webview over
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
    // `artifacts`: the download — the report's last lines. Vite runs before cargo,
    // so these are the PREVIOUS shell's sizes until `phaze native build --bundles
    // app,dmg` runs again; each row says so. Bundles land in target/release/bundle/
    // macos/ (Tauri's layout); the dmg carries the crate version and the arch.
    native({
      // The app's identity: the name a person sees, the bundle's file name — pinned, so the
      // installed path stays /Applications/NeuralkitCLI.app — and the App ID it is signed as.
      name: 'NEURALKIT ™ CLI',
      fileName: 'NeuralkitCLI',
      identifier: 'ai.neuralkit.cli',
      shell: 'wry',
      compress: 'gzip',
      devStylesheets: ['/src/styles.css'],
      artifacts: {
        binary: '../target/release/neuralkit',
        app:    '../target/release/bundle/macos/NeuralkitCLI.app',
        dmg:    '../target/release/bundle/macos/NeuralkitCLI_0.1.0_aarch64.dmg',
      },
    }),
    // StepIndicator.phaze's layout IS Tailwind utilities (`relative` + `absolute
    // left-0 top-0` positioning every dot). Without the plugin those classes generate
    // nothing and every span collapses to width 0 in the same spot — measured, not
    // assumed. `src/styles.css` carries the `@source` that makes Tailwind scan the
    // out-of-tree file — required, and verified against a COLD build.
    tailwindcss(),
    // Fabric's shaker, as in neuralkit-web's config: the transform-stage region
    // strips (SDF_TYPE / SHADER / MODIFIER, RIG / GLASS / MESH features) that keep the
    // shader correct and small, plus the COND_FEATURE strips — fabric's `import()` sites
    // behind runtime conditions (`stats`, `showAxes`, `geometryUrl`, background mips) are
    // removed when this app's source never turns the condition on, so the bundler never
    // emits the chunk and the binary never embeds it. Detection is an fs-walk of `src/`
    // (the cwd's, i.e. this panel's). `regionsOnly` as in -web.
    // `PANEL_NO_SHAKE=1 pnpm build` leaves the shaker out — the one-line bisection
    // for "did a region strip change what fabric draws".
    //
    // BEFORE `glsl()`, as in -web (11f18b1 there): both are `enforce: 'pre'`, so array order
    // decides who transforms a `.wgsl` first, and glsl's chunk loader drops `//` comments —
    // the region markers — whatever its options. Listed after it, as this config had it since
    // be029b7, the shaker saw sdf.wgsl with no markers and stripped nothing there.
    ...(process.env.PANEL_NO_SHAKE ? [] : [fabricShakePlugin({ regionsOnly: true })]),
    // `glsl` resolves fabric's WGSL `#include` graph and minifies it. `minify`, not `compress`:
    // `compress` is the option's pre-1.4 name, which 1.6 ignores (c8e4877 in -web, which this
    // line was copied from before that fix). `warnDuplicatedImports: false` because fabric
    // deliberately includes each material from both the fs and fs_fast pipelines — same flags
    // neuralkit-web uses.
    glsl({ minify: true, warnDuplicatedImports: false }),
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
        sdfGrid:      'first SDF shape mount (the spatial-grid compute shader)',
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
        { name: 'views',      match: (c) => !c.chunkName.startsWith('phaze') && c.moduleIds.some((m) => m.includes('/src/views/')) },
        { name: 'phaze',      match: (c) => c.chunkName === 'phaze' || c.chunkName.startsWith('phaze-')
                                || ['store', 'portal', 'catch', 'time', 'match', 'list', 'defer', 'revalidate'].includes(c.chunkName) },
        { name: 'components', match: (c) => c.moduleIds.some((m) => m.includes('/src/components/') && !m.includes('/fabric/')) },
        { name: 'graviton',   match: (c) => c.moduleIds.some((m) => m.includes('/graviton/')) },
        { name: 'fabric',     match: (c) => c.moduleIds.some((m) => m.includes('/fabric/')) },
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
              // async chunks (named here they would join the eager chunk). Matched
              // with or without a `(group)/` segment, as -web matches FabricCanvas,
              // so a later move into a label folder does not drop it into
              // ui-components.
              if (/\/src\/components\/(?:\([^)]+\)\/)?FabricCube\.tsx$/.test(id)) return 'fabric-cube'
              // Graviton — one chunk for the whole package.
              if (id.includes('/graviton/')) return 'graviton'
              // Photon and the shared -web components → ui-components, as in -web.
              if (id.includes('/photon/')) return 'ui-components'
              // `!/fabric/`: the package's own `src/components/` (Grid, Rig, Wave, StatsHUD) are
              // fabric's, not this app's.
              if (id.includes('/src/components/') && !id.includes('/fabric/')) return 'ui-components'
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
  optimizeDeps: { exclude: ['@madenowhere/phaze', '@madenowhere/phaze-native', '@madenowhere/photon', '@madenowhere/graviton', '@madenowhere/fabric'] },
  // THE PANEL'S OWN PORT, STRICT. -web's dev server holds 5173 on this machine; without
  // `strictPort` Vite would move to 5174 while `phaze native dev` waited on the port in
  // Cargo.toml's `dev-url` — answered by -web — and the shell would show -web's landing page
  // (measured 2026-09-05). Now a taken port fails Vite out loud instead, and the CLI refuses
  // to start when something else already answers on `dev-url`.
  server: { port: 5180, strictPort: true, fs: { allow: ['/Users/r/Minilab/phaze', '/Users/r/Minilab/photon', '/Users/r/Minilab/graviton', '/Users/r/Minilab/fabric', WEB, '.'] } },
})
