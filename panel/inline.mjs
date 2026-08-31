// Fold the built app into ONE self-contained HTML file.
//
// panel.rs delivers the page with wry's `with_html`, which takes a string and
// gives the document no base URL — so nothing with a `src`/`href` can resolve.
// Inlining is what lets that stay true: the Rust side keeps `include_str!` +
// `with_html`, "no path to get wrong", and no custom protocol.
//
// Plain Node on purpose: no plugin, nothing to keep in step with Vite 8.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const dist = new URL('./dist/', import.meta.url).pathname
let html = readFileSync(join(dist, 'index.html'), 'utf8')

const read = (src) => readFileSync(join(dist, src.replace(/^\//, '')), 'utf8')

// <script type="module" src="…"> → the module source itself
html = html.replace(
  /<script\b[^>]*\bsrc="([^"]+)"[^>]*><\/script>/g,
  (_m, src) => `<script type="module">${read(src)}</script>`,
)

// <link rel="stylesheet" href="…"> → a <style> block
html = html.replace(
  /<link\b[^>]*\brel="stylesheet"[^>]*\bhref="([^"]+)"[^>]*>/g,
  (_m, href) => `<style>${read(href)}</style>`,
)

const out = join(dist, 'panel.html')
writeFileSync(out, html)

const left = readdirSync(dist).filter((f) => /\.(js|css)$/.test(f))
console.log(`panel.html  ${(Buffer.byteLength(html) / 1024).toFixed(1)} kB`)
if (/\bsrc="|\bhref="/.test(html)) {
  console.error('STILL REFERENCES A FILE — with_html would load it as a blank page')
  process.exit(1)
}
console.log(`inlined ${left.length} asset${left.length === 1 ? '' : 's'}`)
