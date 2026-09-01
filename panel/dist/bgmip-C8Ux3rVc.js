async function e(e){if(!(e.bgMipPipeline||e._bgMipLoading)){e._bgMipLoading=!0;try{let t=e.device,n=t.createShaderModule({code:`
@group(0) @binding(0) var srcTex:     texture_2d<f32>;
@group(0) @binding(1) var srcSampler: sampler;

struct VsOut { @builtin(position) pos: vec4f, @location(0) uv: vec2f }

@vertex
fn vs(@builtin(vertex_index) i: u32) -> VsOut {
  // One triangle covering all of NDC; out-of-bounds corners get clipped.
  let pos = array<vec2f, 3>(vec2f(-1.0, -1.0), vec2f(3.0, -1.0), vec2f(-1.0, 3.0));
  var out: VsOut;
  out.pos = vec4f(pos[i], 0.0, 1.0);
  // UV in [0,1]; Y flip for top-left texture origin.
  out.uv  = (pos[i] * vec2f(0.5, -0.5)) + vec2f(0.5, 0.5);
  return out;
}

@fragment
fn fs(@location(0) uv: vec2f) -> @location(0) vec4f {
  // Linear sample of the previous mip = box-filter downsample for free.
  return textureSampleLevel(srcTex, srcSampler, uv, 0.0);
}
`});e.bgMipPipeline=t.createRenderPipeline({layout:`auto`,vertex:{module:n,entryPoint:`vs`},fragment:{module:n,entryPoint:`fs`,targets:[{format:e.canvasFormat}]},primitive:{topology:`triangle-list`}})}finally{e._bgMipLoading=!1,e.bgMipBindGroups=null,e.bgMipDstViews=null,e.renderDirtyFrames=Math.max(e.renderDirtyFrames,2)}}}export{e as initBgMip};