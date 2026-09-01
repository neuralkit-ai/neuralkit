// FabricCanvas's shape, one box instead of the full scene. Fabric comes from neuralkit-web's tree
// via the `@web/` alias — no copy. No `Flow('nk:flow', …)`: it lives in phaze-cloudflare, which
// this app does not depend on, and it exists to carry cursor state across sibling ORIGINS.

import { useGraviton } from '@web/lib/fabric/hooks/useGraviton'
import { Camera, Scene, View } from '@web/lib/fabric'
import { Box } from '@web/lib/fabric/shapes'
import { CameraProps, SceneProps } from '@web/lib/fabric'
import { CameraState, SceneState } from '@web/lib/fabric/core/types'
import { GridProps } from '@web/lib/fabric/components/Grid'

const IS_RETINA = typeof window !== 'undefined' && window.devicePixelRatio > 1

const DEFAULT_CAMERA: CameraState = {
  fov: 60, zoom: 1, cameraZ: 8, cameraMode: 0, rigMode: 0,
  warpStrength: 3.0, warpRadius: 4.0,
  pointerZ: 0, pointerFalloff: 0,
  easing: 5, range: { x: 2, y: 1 }, zDolly: 2,
  trackMouse: true, trackDevice: true,
}

const DEFAULT_GRID: GridProps = {
  speed: 3, curl: 0.04, amplitude: 0, distance: 0,
  color: '#000', focusColor: '#00ff0d',
  pointsize: IS_RETINA ? 6 : 3.5,
  gridSpacing: IS_RETINA ? 0.6 : 0.4,
  resolution: 64,
  highlightFocus: false,
  useSlots: false, slotRadius: 0.05, slotLength: 1, slotSize: 10,
  usePlyColor: false,
  focus: 8, aperture: 5.6,
}

const DEFAULT_SCENE: SceneProps = {
  translateX: 0, translateY: 0, translateZ: 0,
  rotationX: 0, rotationY: 0, rotationZ: 0,
  showAxes: false,
  fps: 60,
  maxSteps: 32,
  sdfEpsilon: 0.004,
  lodScaling: 0.0,
  edgeSoftness: 1.0,
  stepRelaxation: 1.0,
  stats: false,
  debugMode: false,
  enableReflection: false,
}

const DEFAULT_FULL_SCENE: SceneState = {
  ...DEFAULT_GRID,
  ...DEFAULT_SCENE,
} as SceneState

type Props = {
  className?: string
  camera?: CameraProps
  scene?: SceneProps
}

export function FabricCube({ className, camera, scene }: Props) {
  if (typeof window === 'undefined') return null

  const fabric = useGraviton(DEFAULT_CAMERA, DEFAULT_FULL_SCENE)

  const activeCamera = { ...DEFAULT_CAMERA, ...camera }
  const activeScene  = { ...DEFAULT_SCENE,  ...scene  }

  return (
    <>
      <Camera {...activeCamera} />
      <Scene {...activeScene} />

      <Box position={[0, 0, 0]} size={1} rotation={[0.6, 0.8, 0]} roundness={0.08} color="#5ac8fa" />

      <View track={fabric} />

      <canvas
        ref={fabric.canvas}
        class={className}
        style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' }}
      />
    </>
  )
}
