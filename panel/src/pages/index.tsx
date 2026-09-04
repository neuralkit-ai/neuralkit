// The welcome card, as a Phaze page. `native()` generates it at build into
// `dist/index.html` and the webview hydrates it; the Rust side embeds that one
// document. The card's copy is in the HTML before any script runs.

import '../styles.css'
import { listen } from '@madenowhere/phaze'
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

  // WKWebView SWALLOWS THE MOUSE, which is why `setMovableByWindowBackground:` stopped working
  // the moment a webview filled the panel: AppKit only drags when the click reaches a view that
  // does not handle it. So the page reports the press and AppKit does the drag —
  // `performWindowDragWithEvent:` runs the real thing, including the screen-edge behaviour.
  // Anything interactive can opt out with `data-no-drag`. Guarded because this body also runs
  // at build, against linkedom, which installs `document` but never `window`.
  if (typeof window !== 'undefined') {
    listen(window, 'mousedown', (e: MouseEvent) => {
      if (e.button !== 0 || (e.target as Element | null)?.closest('[data-no-drag]')) return
      ;(window as Window & { ipc?: { postMessage(m: string): void } }).ipc?.postMessage('drag')
    })
  }

  return (
    <main>
      <FabricCube ssr={false} />
      <h1>Neuralkit CLI is installed</h1>
      <p>The neuralkit command is now on your PATH.</p>

      <StepIndicator state={state} steps={steps} className="mt-1.5 opacity-30" />
    </main>
  )
}
