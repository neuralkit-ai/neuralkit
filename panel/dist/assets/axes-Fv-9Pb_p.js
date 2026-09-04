async function e(e){if(!(e.axesPipeline||e._axesLoading)){e._axesLoading=!0;try{let t=e.device,n=t.createShaderModule({code:`
struct RenderUniforms {
  mvpMatrix:          mat4x4f,
  modelViewMatrix:    mat4x4f,
  color:              vec4f,
  focusColor:         vec4f,
  cameraPos:          vec4f,
  pointerAndViewport: vec4f,
  params0:            vec4f,
  params1:            vec4f,
  params2:            vec4f,
  params3:            vec4f,
  params4:            vec4f,
  vpMatrix:           mat4x4f,
  viewMatrix:         mat4x4f,
  extraParams:        vec4f,
  perfParams:         vec4f,
  fastEffectGlow:     vec4f,
  fastEffectOutline:  vec4f,
  fastEffectScalars:  vec4f,
  _reserved120:       vec4f,
}
@group(0) @binding(1) var<uniform> uni: RenderUniforms;

struct VertexOutput { @builtin(position) pos: vec4f, @location(0) col: vec4f }
@vertex
fn vs(@builtin(vertex_index) i: u32) -> VertexOutput {
  let p = array<vec3f,6>(vec3f(0),vec3f(1,0,0),vec3f(0),vec3f(0,1,0),vec3f(0),vec3f(0,0,1));
  let c = array<vec4f,6>(vec4f(1,.2,.2,1),vec4f(1,.2,.2,1),vec4f(.2,1,.2,1),vec4f(.2,1,.2,1),vec4f(.2,.4,1,1),vec4f(.2,.4,1,1));
  var out: VertexOutput;
  let camPos = uni.cameraPos.xyz;
  let pointer = uni.pointerAndViewport.xy;
  let targetDist = camPos.z - uni.params2.y;
  let viewScale = 2.*targetDist*tan(uni.params1.x*.5*3.14159265/180.)/uni.params1.y;
  let origin = vec3f(camPos.x+pointer.x*viewScale*.5*uni.params1.z, camPos.y+pointer.y*viewScale*.5, uni.params2.y);
  out.pos = uni.vpMatrix * vec4f(p[i]+origin, 1.);
  out.col = c[i];
  return out;
}
@fragment
fn fs(in: VertexOutput) -> @location(0) vec4f { return vec4f(in.col.rgb*in.col.a, in.col.a); }
`}),r=e.renderPipeline.getBindGroupLayout(0);e.axesPipeline=t.createRenderPipeline({layout:t.createPipelineLayout({bindGroupLayouts:[r]}),vertex:{module:n,entryPoint:`vs`},fragment:{module:n,entryPoint:`fs`,targets:[{format:e.canvasFormat,blend:{color:{srcFactor:`one`,dstFactor:`one-minus-src-alpha`,operation:`add`},alpha:{srcFactor:`one`,dstFactor:`one-minus-src-alpha`,operation:`add`}}}]},primitive:{topology:`line-list`},depthStencil:{format:`depth24plus`,depthWriteEnabled:!1,depthCompare:`always`}})}finally{e._axesLoading=!1,e.renderDirtyFrames=2}}}export{e as initAxes};