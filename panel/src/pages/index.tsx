// The welcome card, as a Phaze page. `native()` generates it at build into
// `dist/index.html` and the webview hydrates it; the Rust side embeds that one
// document. The card's copy is in the HTML before any script runs.

import '../styles.css'
import { drag } from '@madenowhere/phaze-native/wry'
import { s } from '@madenowhere/phaze/dsl'
import { inc } from '@madenowhere/phaze/numeric'
import { interval, seconds } from '@madenowhere/phaze/time'
// THE one definition — neuralkit-web's. `@web/` is aliased in vite.config.ts.
import { StepIndicator } from '@web/components/ui/StepIndicator.phaze'
import { FabricCube } from '../FabricCube'

export const head = { title: 'Neuralkit' }

export default function Welcome() {
  const state = s<'intake' | 'signal' | 'model' | 'report'>('intake')
  const steps = s(['intake', 'signal', 'model', 'report'])

  interval(seconds(3), inc(state))

  // The whole card is a drag handle (`data-tauri-drag-region` on <main>, matched
  // with `closest`, so the copy inside drags too); anything interactive opts out
  // with `data-no-drag`. Why the page is involved at all — WKWebView swallows the
  // mouse, so the page reports the press and AppKit runs the real drag — is the
  // shell binding's to explain; panel.rs answers the `drag` message it posts.
  drag()

  return (
    <main data-tauri-drag-region>
      <FabricCube ssr={false} />
      <h1>Neuralkit CLI is installed</h1>
      <p>The neuralkit command is now on your PATH.</p>

      <StepIndicator state={state} steps={steps} className="mt-1.5 opacity-30" />
    </main>
  )
}
