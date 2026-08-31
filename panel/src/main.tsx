import './styles.css'
import { render } from '@madenowhere/phaze'
import { s } from '@madenowhere/phaze/dsl'
import { inc } from '@madenowhere/phaze/numeric'
import { interval, seconds } from '@madenowhere/phaze/time'
import { StepIndicator } from './StepIndicator.phaze'

// The welcome card, as a phaze app rather than a Rust string literal. The copy is
// the same one `panel.rs` shipped inline; what is new is that it can hold live
// state — the indicator below advances on its own, which a `&str` could not do.
function App() {
  const state = s<'intake' | 'signal' | 'model' | 'report'>('intake')
  const steps = s(['intake', 'signal', 'model', 'report'])

  interval(seconds(3), inc(state))

  return (
    <main>
      <h1>Neuralkit CLI is installed</h1>
      <p>The neuralkit command is now on your PATH.</p>

      <StepIndicator state={state} steps={steps} className="mt-1.5" />

      <ul>
        <li><code>neuralkit auth login</code><span>sign in</span></li>
        <li><code>neuralkit --help</code><span>everything else</span></li>
      </ul>
    </main>
  )
}

render(App, document.getElementById('app')!)
