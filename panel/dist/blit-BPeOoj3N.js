async function e(e){if(!(e.blitPipeline||e._blitLoading)){e._blitLoading=!0;try{let t=e.device,n=t.createShaderModule({code:`
@group(0) @binding(0) var srcTex:     texture_2d<f32>;
@group(0) @binding(1) var srcSampler: sampler;

struct VsOut { @builtin(position) pos: vec4f, @location(0) uv: vec2f }

@vertex
fn vs(@builtin(vertex_index) i: u32) -> VsOut {
  let pos = array<vec2f, 3>(vec2f(-1.0, -1.0), vec2f(3.0, -1.0), vec2f(-1.0, 3.0));
  var out: VsOut;
  out.pos = vec4f(pos[i], 0.0, 1.0);
  out.uv  = (pos[i] * vec2f(0.5, -0.5)) + vec2f(0.5, 0.5);
  return out;
}

@fragment
fn fs(@location(0) uv: vec2f) -> @location(0) vec4f {
  return textureSampleLevel(srcTex, srcSampler, uv, 0.0);
}
`});e.blitPipeline=t.createRenderPipeline({layout:`auto`,vertex:{module:n,entryPoint:`vs`},fragment:{module:n,entryPoint:`fs`,targets:[{format:e.canvasFormat}]},primitive:{topology:`triangle-list`}}),e.blitSampler||=t.createSampler({magFilter:`linear`,minFilter:`linear`})}finally{e._blitLoading=!1,e.blitBindGroup=null,e.renderDirtyFrames=Math.max(e.renderDirtyFrames,2)}}}export{e as initBlit};