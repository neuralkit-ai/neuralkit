// Ambient declaration that makes TypeScript accept `.phaze` files as
// modules. Exports are typed as `any` because there's no LSP yet — the
// full type-aware path is the Volar adapter (tracked as Phase 3).
//
// `pnpm check` (phaze-check) already resolves `.phaze` on its own and passes
// without this; the editor's plain TS service does not, which is what the file
// is here for. Same copy neuralkit-web carries at src/phaze-modules.d.ts.
//
// Drop this file when phaze-language-tools (Volar) lands; the adapter
// will provide real types via the .phaze → .tsx pre-processor + a
// sourcemap, replacing this with checked types from the synthesized
// .tsx.
declare module '*.phaze'
