import './styles.css'
import { render } from '@madenowhere/phaze'
import { s } from '@madenowhere/phaze/dsl'
import { inc } from '@madenowhere/phaze/numeric'
import { interval, seconds } from '@madenowhere/phaze/time'
// THE one definition — neuralkit-web's. `@web/` is aliased in vite.config.ts.
import { StepIndicator } from '@web/components/ui/StepIndicator.phaze'
import { FabricCube } from './FabricCube'


function App() {
  const state = s<'intake' | 'signal' | 'model' | 'report'>('intake')
  const steps = s(['intake', 'signal', 'model', 'report'])

  interval(seconds(3), inc(state))

  return (
    <main>
      <FabricCube />
      <h1>Neuralkit CLI is installed</h1>
      <p>The neuralkit command is now on your PATH.</p>

      <StepIndicator state={state} steps={steps} className="mt-1.5 opacity-30" />

    </main>
  )
}

render(App, document.getElementById('app')!)
