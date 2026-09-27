import { JSXChild } from '@madenowhere/phaze'
import { FabricCube } from './FabricCube'

// The app shell's markup: the card as a drag handle (`data-tauri-drag-region`,
// which app.phaze's `drag()` reads) and the cube, then the page.
//
// A component, not markup in app.phaze, for the reason neuralkit-web's App
// wraps its page in one: a component's children compile to `() => children`,
// so appendDynamicChild's two hydration calls (the peek, then
// withoutHydration) each return the router's `currentView` without calling it,
// and the page is built once. `{children}` written bare in app.phaze's own
// markup is passed as `currentView` itself, and the withoutHydration call
// builds the page a second time, its effects included — the welcome view's
// `interval` ran twice (phaze's reference/ssr.mdx, "Component boundaries and
// dynamic children").
type Props = {
  children?: JSXChild
}

export function Layout({ children }: Props) {
  return (
    <main data-tauri-drag-region>
      <FabricCube ssr={false} />
      {children}
    </main>
  )
}
