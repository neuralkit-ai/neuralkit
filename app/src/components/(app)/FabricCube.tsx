// FabricCanvas's shape, one box instead of the full scene. Fabric comes from neuralkit-web's tree
// via the `@web/` alias — no copy. No `Flow('nk:flow', …)`: it lives in phaze-cloudflare, which
// this app does not depend on, and it exists to carry cursor state across sibling ORIGINS.
//
// THE BOX IS -WEB'S, VERBATIM — the `<Effect>` + `<Box>` block from FabricCanvas.tsx, comments
// included, so the two render the same object and this card is the reference for matching the
// web's look under wry. `flux` is the empty object FabricCanvas keeps commented beside its real
// one (`//const flux: any = {}`), so every `flux.x ?? default` in the block resolves to the
// default; `capsuleGlow` is FabricCanvas's own line. Uncommenting the glass variant needs a
// REBUILD, not just a reload: the shaker reads `shader: 'glass'` from this source to keep the
// glass shader and the background mips in the build.

import { photonValue } from '@madenowhere/photon/phaze'
import { useGraviton } from '@web/lib/fabric/hooks/useGraviton'
import { Camera, Scene, View } from '@web/lib/fabric'
import { Box } from '@web/lib/fabric/shapes'
import { Effect } from '@web/lib/fabric/Composers'
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

  const boxGlow   = photonValue(0.2)
  const flux: any = {}

  return (
    <>
      <Camera {...activeCamera} />
      <Scene {...activeScene} />

      <Effect
            //outline={{ thickness: 0.1, color: '#00000020', merge: false }}
            glow={{ intensity: boxGlow, color: '#00ff66', radius: 0.2 }}
          >
           
            <Box
              position={[0, 0, 0]}
              rotation={[flux.cube3RotX ?? 30, flux.cube3RotY ?? 30, flux.cube3RotZ ?? 0]}
              size={{ x: 0.6, y: 0.6, z: 0.6 }}
              roundness={0.4}
              color="#ef23db"
              material={{
                ambient: 0.3,
                shader: 'phong',
                roughness: 0.004,
                roughnessScale: 6.0,
              }}
              // Glass variant:
              // material={{
              //   shader:              'glass',
              //   thickness:           (flux.sdfThickness           ?? 2)         as any,
              //   ior:                 (flux.sdfIor                 ?? 0.79)      as any,
              //   fresnel:             (flux.sdfFresnel             ?? 9)         as any,
              //   fresnelColor:        (flux.sdfFresnelColor        ?? '#ffffff') as any,
              //   outline:             (flux.sdfOutline             ?? 0.4)       as any,
              //   attenuationDistance: (flux.sdfAttenuationDistance ?? 100)       as any,
              //   attenuationColor:    (flux.sdfAttenuationColor    ?? '#ffffff') as any,
              //   distortion:          (flux.sdfDistortion          ?? 0.0)       as any,
              //   distortionScale:     (flux.sdfDistortionScale     ?? 1.0)       as any,
              //   anisotropy:          (flux.sdfAnisotropy          ?? 0.0)       as any,
              //   anisotropyRotation:  (flux.sdfAnisotropyRotation  ?? 0.0)       as any,
              //   anisotropyBlur:      (flux.sdfAnisotropyBlur      ?? 0.0)       as any,
              //   grain:               (flux.sdfGrain               ?? 0.0)       as any,
              //   grainScale:          (flux.sdfGrainScale          ?? 0)         as any,
              //   iridescence:         (flux.sdfIridescence         ?? 0.0)       as any,
              //   iridescenceThickness:(flux.sdfIridescenceThickness ?? 400)      as any,
              //   clearcoat:           (flux.sdfClearcoat           ?? 0.0)       as any,
              //   clearcoatRoughness:  (flux.sdfClearcoatRoughness  ?? 0.0)       as any,
              //   sheen:               (flux.sdfSheen               ?? 0.0)       as any,
              //   sheenColor:          (flux.sdfSheenColor          ?? '#ffffff') as any,
              //   reflection:          (flux.sdfReflection          ?? 0.0)       as any,
              //   reflectionRoughness: (flux.sdfReflectionRoughness ?? 0.0)       as any,
              //   temporalDistortion:  (flux.sdfTemporalDistortion  ?? 0.0)       as any,
              //   metalness:           (flux.sdfMetalness           ?? 0.0)       as any,
              //   color:               (flux.sdfBgColor             ?? '#ececec') as any,
              //   innerSteps:          (flux.sdfInnerSteps          ?? 32)        as any,
              //   chromaticAberration: (flux.sdfChromaticAberration ?? 0.02)      as any,
              //   roughness:           (flux.sdfBlur                ?? 0.10)      as any,
              //   gloss:               (flux.sdfGloss               ?? 0.0)       as any,
              //   glossSharpness:      (flux.sdfGlossSharpness      ?? 0.7)       as any,
              //   glossCoverage:       (flux.sdfGlossCoverage       ?? 0.18)      as any,
              // }}
            />
          </Effect>

      <View track={fabric} />

      <canvas
        ref={fabric.canvas}
        class={className}
        style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' }}
      />
    </>
  )
}
