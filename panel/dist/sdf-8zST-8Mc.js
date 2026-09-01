var e=`struct RenderUniforms {
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
  
  
  
  bgParams:           vec4f
}

struct Object {
  pos_rounding:    vec4f, 
  size_type:       vec4f, 
  rotation:        vec3f, 
  hColor:          u32,   
  material:        vec4u, 
  glow_color:      u32,   
  glow_intensity:  f32,
  glow_radius:     f32,
  
  
  
  packed_reserved: u32,
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  modifier:        vec4f,
  
  
  
  
  
  
  modifier2:       vec4f,
  
  
  
  modifier3:       vec4f,
  
  
  
  modifier4:       vec4f,
  
  
  
  
  
  modifier5:       vec4f,
  
  
  
  modifier6:       vec4f,
  
  
  
  
  
  modifier7:       vec4f,
  
  
  
  
  
  modifier8:       vec4f
}

struct Cell {
  count: u32,
  indices: array<u32, 15>,
}
struct Grid {
  cells: array<Cell, 32768>,
}

@group(0) @binding(1) var<uniform> uni: RenderUniforms;
@group(0) @binding(3) var<storage, read> objects: array<Object>;
@group(0) @binding(4) var<storage, read> grid: Grid;

fn sdBox(p: vec3f, b: vec3f) -> f32 {
  let q = abs(p) - b;
  return length(max(q, vec3f(0.0))) + min(max(q.x, max(q.y, q.z)), 0.0);
}
fn sdCapsule(p: vec3f, h: f32, r: f32) -> f32 {
  var q = p;
  q.y -= clamp(p.y, -h, h);
  return length(q) - r;
}
fn sdSphere(p: vec3f, r: f32) -> f32 {
  return length(p) - r;
}
fn sdTorus(p: vec3f, ra: f32, rb: f32) -> f32 {
  let q = vec2f(length(p.xz) - ra, p.y);
  return length(q) - rb;
}

fn sdCappedTorus(p: vec3f, sc: vec2f, ra: f32, rb: f32) -> f32 {
  var q = p;
  q.x = abs(q.x);
  var k = 0.0;
  if (sc.y * q.x > sc.x * q.z) { k = dot(q.xz, sc); } else { k = length(q.xz); }
  return sqrt(dot(q.xz, q.xz) + q.y * q.y + ra * ra - 2.0 * ra * k) - rb;
}
fn sdPlane(p: vec3f, b: vec3f, r: f32) -> f32 {
  let rc = min(r, min(b.x, b.y));

  
  let q2 = abs(p.xy) - b.xy + vec2f(rc);
  let d2 = length(max(q2, vec2f(0.0))) + min(max(q2.x, q2.y), 0.0) - rc;

  
  let w = vec2f(d2, abs(p.z) - b.z);
  return min(max(w.x, w.y), 0.0) + length(max(w, vec2f(0.0)));
}
fn sdConeFinite(p: vec3f, radius: f32, halfH: f32) -> f32 {
  let pc = vec3f(p.x, p.y - halfH, p.z);  
  let q = vec2f(radius, -2.0 * halfH);
  let w = vec2f(length(pc.xz), pc.y);
  let a = w - q * clamp(dot(w, q) / dot(q, q), 0.0, 1.0);
  let b = w - q * vec2f(clamp(w.x / q.x, 0.0, 1.0), 1.0);
  let k = sign(q.y);
  let d = min(dot(a, a), dot(b, b));
  let s = max(k * (w.x * q.y - w.y * q.x), k * (w.y - q.y));
  return sqrt(d) * sign(s);
}
fn sdCylinder(p: vec3f, radius: f32, halfH: f32) -> f32 {
  let d = vec2f(length(p.xz) - radius, abs(p.y) - halfH);
  return min(max(d.x, d.y), 0.0) + length(max(d, vec2f(0.0)));
}
fn sdRoundedCylinder(p: vec3f, ra: f32, rb: f32, halfH: f32) -> f32 {
  let rbc = min(rb, min(ra, halfH));
  let d = vec2f(length(p.xz) - ra + rbc, abs(p.y) - halfH + rbc);
  return min(max(d.x, d.y), 0.0) + length(max(d, vec2f(0.0))) - rbc;
}
fn sdCappedCone(p: vec3f, halfH: f32, r1: f32, r2: f32) -> f32 {
  let q = vec2f(length(p.xz), p.y);
  let k1 = vec2f(r2, halfH);
  let k2 = vec2f(r2 - r1, 2.0 * halfH);
  let ca = vec2f(q.x - min(q.x, select(r2, r1, q.y < 0.0)), abs(q.y) - halfH);
  let cb = q - k1 + k2 * clamp(dot(k1 - q, k2) / dot(k2, k2), 0.0, 1.0);
  let s = select(1.0, -1.0, cb.x < 0.0 && ca.y < 0.0);
  return s * sqrt(min(dot(ca, ca), dot(cb, cb)));
}
fn sdPyramid(p: vec3f, baseHalf: f32, halfH: f32) -> f32 {
  
  let pBase = vec3f(p.x, p.y + halfH, p.z);
  let s = max(2.0 * baseHalf, 0.001);    
  let h = halfH / max(baseHalf, 0.001);  
  var ps = vec3f(pBase.x / s, pBase.y / s, pBase.z / s);

  let m2 = h * h + 0.25;
  ps = vec3f(abs(ps.x), ps.y, abs(ps.z));
  ps = select(ps, vec3f(ps.z, ps.y, ps.x), ps.z > ps.x);
  ps = vec3f(ps.x - 0.5, ps.y, ps.z - 0.5);
  let q = vec3f(ps.z, h * ps.y - 0.5 * ps.x, h * ps.x + 0.5 * ps.y);
  let s2 = max(-q.x, 0.0);
  let t = clamp((q.y - 0.5 * ps.z) / (m2 + 0.25), 0.0, 1.0);
  let a = m2 * (q.x + s2) * (q.x + s2) + q.y * q.y;
  let b = m2 * (q.x + 0.5 * t) * (q.x + 0.5 * t) + (q.y - m2 * t) * (q.y - m2 * t);
  
  
  
  
  let d2 = select(min(a, b), 0.0, min(q.y, -q.x * m2 - q.y * 0.5) > 0.0);
  return sqrt((d2 + q.z * q.z) / m2) * sign(max(q.z, -ps.y)) * s;
}
fn sdOctahedron(p: vec3f, size: f32) -> f32 {
  let pa = vec3f(abs(p.x), abs(p.y), abs(p.z));
  let m = pa.x + pa.y + pa.z - size;
  var q: vec3f;
  if (3.0 * pa.x < m)      { q = pa.xyz; }
  else if (3.0 * pa.y < m) { q = pa.yzx; }
  else if (3.0 * pa.z < m) { q = pa.zxy; }
  else                     { return m * 0.57735027; }
  let k = clamp(0.5 * (q.z - q.y + size), 0.0, size);
  return length(vec3f(q.x, q.y - size + k, q.z - k));
}
fn sdHexPrism(p: vec3f, radius: f32, halfH: f32) -> f32 {
  let k = vec3f(-0.8660254, 0.5, 0.57735);
  let pa = vec3f(abs(p.x), abs(p.y), abs(p.z));
  let xz = pa.xz - 2.0 * min(dot(k.xy, pa.xz), 0.0) * k.xy;
  let d = vec2f(
    length(xz - vec2f(clamp(xz.x, -k.z * radius, k.z * radius), radius)) * sign(xz.y - radius),
    pa.y - halfH
  );
  return min(max(d.x, d.y), 0.0) + length(max(d, vec2f(0.0)));
}
fn sdEllipsoid(p: vec3f, r: vec3f) -> f32 {
  let k0 = length(p / r);
  let k1 = length(p / (r * r));
  return k0 * (k0 - 1.0) / k1;
}
fn sdTriPrism(p: vec3f, triSize: f32, halfH: f32) -> f32 {
  let q = vec3f(abs(p.x), abs(p.y), abs(p.z));
  return max(q.y - halfH, max(q.x * 0.866025 + p.z * 0.5, -p.z) - triSize * 0.5);
}
fn sdRoundCone(p: vec3f, r1: f32, r2: f32, halfH: f32) -> f32 {
  let h = 2.0 * halfH;
  let pc = vec3f(p.x, p.y + halfH, p.z);  
  let q = vec2f(length(pc.xz), pc.y);
  let b = (r1 - r2) / h;
  let a = sqrt(max(1.0 - b * b, 0.0));
  let k = dot(q, vec2f(-b, a));
  if (k < 0.0) { return length(q) - r1; }
  if (k > a * h) { return length(q - vec2f(0.0, h)) - r2; }
  return dot(q, vec2f(a, b)) - r1;
}
fn sdBoxFrame(p: vec3f, b: vec3f, e: f32) -> f32 {
  let p2 = vec3f(abs(p.x), abs(p.y), abs(p.z)) - b;
  let q = vec3f(abs(p2.x + e), abs(p2.y + e), abs(p2.z + e)) - vec3f(e);
  return min(min(
      length(max(vec3f(p2.x, q.y, q.z), vec3f(0.0))) + min(max(p2.x, max(q.y, q.z)), 0.0),
      length(max(vec3f(q.x, p2.y, q.z), vec3f(0.0))) + min(max(q.x, max(p2.y, q.z)), 0.0)),
      length(max(vec3f(q.x, q.y, p2.z), vec3f(0.0))) + min(max(q.x, max(q.y, p2.z)), 0.0));
}
fn sdRhombus(p: vec3f, la: f32, lb: f32, halfH: f32, ra: f32) -> f32 {
  let pa = vec3f(abs(p.x), abs(p.y), abs(p.z));
  let b = vec2f(la, lb);
  
  let ndotVal = b.x * (b.x - 2.0 * pa.x) - b.y * (b.y - 2.0 * pa.z);
  let f = clamp(ndotVal / dot(b, b), -1.0, 1.0);
  let off = 0.5 * b * vec2f(1.0 - f, 1.0 + f);
  let qx = length(pa.xz - off) * sign(pa.x * b.y + pa.z * b.x - b.x * b.y) - ra;
  let qy = pa.y - halfH;
  return min(max(qx, qy), 0.0) + length(max(vec2f(qx, qy), vec2f(0.0)));
}
fn sdCutSphere(p: vec3f, r: f32, h: f32) -> f32 {
  let w = sqrt(max(r * r - h * h, 0.0));
  let q = vec2f(length(p.xz), p.y);
  let s = max((h - r) * q.x * q.x + w * w * (h + r - 2.0 * q.y), h * q.x - w * q.y);
  if (s < 0.0) { return length(q) - r; }
  if (q.x < w) { return h - q.y; }
  return length(q - vec2f(w, h));
}
fn sdCutHollowSphere(p: vec3f, r: f32, h: f32, t: f32) -> f32 {
  let w = sqrt(max(r * r - h * h, 0.0));
  let q = vec2f(length(p.xz), p.y);
  let d = select(abs(length(q) - r), length(q - vec2f(w, h)), h * q.x < w * q.y);
  return d - t;
}
fn sdDeathStar(p: vec3f, ra: f32, rb: f32, d: f32) -> f32 {
  let a = (ra * ra - rb * rb + d * d) / (2.0 * d);
  let b = sqrt(max(ra * ra - a * a, 0.0));
  let q = vec2f(p.x, length(p.yz));
  if (q.x * b - q.y * a > d * max(b - q.y, 0.0)) {
    return length(q - vec2f(a, b));
  }
  return max(length(q) - ra, -(length(q - vec2f(d, 0.0)) - rb));
}
fn sdSolidAngle(p: vec3f, sc: vec2f, ra: f32) -> f32 {
  let q = vec2f(length(p.xz), p.y);
  let l = length(q) - ra;
  let m = length(q - sc * clamp(dot(q, sc), 0.0, ra));
  return max(l, m * sign(sc.y * q.x - sc.x * q.y));
}
fn sdLink(p: vec3f, le: f32, r1: f32, r2: f32) -> f32 {
  let q = vec3f(p.x, max(abs(p.y) - le, 0.0), p.z);
  return length(vec2f(length(q.xy) - r1, q.z)) - r2;
}

fn sdCircle2D(p: vec2f, r: f32) -> f32 {
  return length(p) - r;
}
fn sdRect2D(p: vec2f, b: vec2f) -> f32 {
  let q = abs(p) - b;
  return length(max(q, vec2f(0.0))) + min(max(q.x, q.y), 0.0);
}
fn sdRoundedRect2D(p: vec2f, b: vec2f, r: f32) -> f32 {
  let rc = min(r, min(b.x, b.y));
  let q = abs(p) - b + vec2f(rc);
  return length(max(q, vec2f(0.0))) + min(max(q.x, q.y), 0.0) - rc;
}

fn hash12(p: vec2f) -> f32 {
  var p3 = fract(p.xyx * 0.1031);
  p3 += dot(p3, p3.yzx + 33.33);
  return fract((p3.x + p3.y) * p3.z);
}

fn noise2D(p: vec2f) -> f32 {
  let i = floor(p);
  let f = fract(p);
  let u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash12(i + vec2f(0.0, 0.0)), hash12(i + vec2f(1.0, 0.0)), u.x),
             mix(hash12(i + vec2f(0.0, 1.0)), hash12(i + vec2f(1.0, 1.0)), u.x), u.y);
}

fn hash13(p: vec3f) -> f32 {
  var p3 = fract(p * 0.1031);
  p3 += dot(p3, p3.yzx + 33.33);
  return fract((p3.x + p3.y) * p3.z);
}

fn noise3D(p: vec3f) -> f32 {
  let i = floor(p);
  let f = fract(p);
  let u = f * f * (3.0 - 2.0 * f);
  return mix(mix(mix(hash13(i + vec3f(0.0, 0.0, 0.0)), hash13(i + vec3f(1.0, 0.0, 0.0)), u.x),
                 mix(hash13(i + vec3f(0.0, 1.0, 0.0)), hash13(i + vec3f(1.0, 1.0, 0.0)), u.x), u.y),
             mix(mix(hash13(i + vec3f(0.0, 0.0, 1.0)), hash13(i + vec3f(1.0, 0.0, 1.0)), u.x),
                 mix(hash13(i + vec3f(0.0, 1.0, 1.0)), hash13(i + vec3f(1.0, 1.0, 1.0)), u.x), u.y), u.z);
}

fn rotateXYZ(p: vec3f, r: vec3f) -> vec3f {
  var q = p;
  let cx = cos(r.x); let sx = sin(r.x);
  q = vec3f(q.x, cx * q.y - sx * q.z, sx * q.y + cx * q.z);
  let cy = cos(r.y); let sy = sin(r.y);
  q = vec3f(cy * q.x + sy * q.z, q.y, -sy * q.x + cy * q.z);
  let cz = cos(r.z); let sz = sin(r.z);
  q = vec3f(cz * q.x - sz * q.y, sz * q.x + cz * q.y, q.z);
  return q;
}

fn rotateZYX(p: vec3f, r: vec3f) -> vec3f {
  var q = p;
  let cz = cos(r.z); let sz = sin(r.z);
  q = vec3f(cz * q.x - sz * q.y, sz * q.x + cz * q.y, q.z);
  let cy = cos(r.y); let sy = sin(r.y);
  q = vec3f(cy * q.x + sy * q.z, q.y, -sy * q.x + cy * q.z);
  let cx = cos(r.x); let sx = sin(r.x);
  q = vec3f(q.x, cx * q.y - sx * q.z, sx * q.y + cx * q.z);
  return q;
}

struct SDFResult {
  dist: f32,
  idx:  u32
}

fn evalObjectSDF(p: vec3f, i: u32) -> f32 {
  let o = objects[i];
  var pTr = rotateZYX(p - o.pos_rounding.xyz, -o.rotation.xyz);
  var d = 1e4;

  let typeId = o.size_type.w;

  
  
  
  
  
  
  
  
  
  
  
  
  let pA          = unpackPropsA(o.material.z);
  let isGlass     = u32(pA.z) == 7u;
  let modMask     = select(u32(o.modifier.x), 0u, isGlass);
  if (modMask != 0u) {
    
    
    if ((modMask & 0x80u) != 0u) {
      let h = o.modifier3.xyz;
      pTr = pTr - clamp(pTr, -h, h);
    }
    
    if ((modMask & 0x2u) != 0u) { pTr.x = abs(pTr.x); }
    if ((modMask & 0x4u) != 0u) { pTr.y = abs(pTr.y); }
    if ((modMask & 0x8u) != 0u) { pTr.z = abs(pTr.z); }
    
    if ((modMask & 0x20u) != 0u) {
      let k = o.modifier.w;
      let c = cos(k * pTr.x);
      let s = sin(k * pTr.x);
      pTr = vec3f(c * pTr.x - s * pTr.y, s * pTr.x + c * pTr.y, pTr.z);
    }
    
    if ((modMask & 0x10u) != 0u) {
      let k = o.modifier.z;
      let c = cos(k * pTr.y);
      let s = sin(k * pTr.y);
      pTr = vec3f(c * pTr.x - s * pTr.z, pTr.y, s * pTr.x + c * pTr.z);
    }
  }

  if (typeId < 0.5) {
    
    d = sdBox(pTr, o.size_type.xyz) - o.pos_rounding.w;
  } else if (typeId < 1.5) {
    
    d = sdCapsule(pTr, o.size_type.y, o.size_type.x);
  } else if (typeId < 2.5) {
    
    d = sdSphere(pTr, o.size_type.x);
  } else if (typeId < 3.5) {
    
    let ra = o.size_type.x;
    let rb = o.size_type.y;
    let angle = o.size_type.z;
    if (angle > 0.0) {
      let sc = vec2f(sin(angle), cos(angle));
      d = sdCappedTorus(pTr, sc, ra, rb);
    } else {
      d = sdTorus(pTr, ra, rb);
    }
  } else if (typeId < 4.5) {
    
    d = sdPlane(pTr, o.size_type.xyz, o.pos_rounding.w);
  } else if (typeId < 5.5) {
    
    d = sdConeFinite(pTr, o.size_type.x, o.size_type.y);
  } else if (typeId < 6.5) {
    
    d = sdCylinder(pTr, o.size_type.x, o.size_type.y);
  } else if (typeId < 7.5) {
    
    d = sdRoundedCylinder(pTr, o.size_type.x, o.pos_rounding.w, o.size_type.y);
  } else if (typeId < 8.5) {
    
    d = sdCappedCone(pTr, o.size_type.y, o.size_type.x, o.size_type.z);
  } else if (typeId < 9.5) {
    
    d = sdPyramid(pTr, o.size_type.x, o.size_type.y);
  } else if (typeId < 10.5) {
    
    d = sdOctahedron(pTr, o.size_type.x);
  } else if (typeId < 11.5) {
    
    d = sdHexPrism(pTr, o.size_type.x, o.size_type.y);
  } else if (typeId < 12.5) {
    
    d = sdEllipsoid(pTr, o.size_type.xyz);
  } else if (typeId < 13.5) {
    
    d = sdTriPrism(pTr, o.size_type.x, o.size_type.y);
  } else if (typeId < 14.5) {
    
    d = sdRoundCone(pTr, o.size_type.x, o.size_type.z, o.size_type.y);
  } else if (typeId < 15.5) {
    
    d = sdBoxFrame(pTr, o.size_type.xyz, o.pos_rounding.w);
  } else if (typeId < 16.5) {
    
    d = sdRhombus(pTr, o.size_type.x, o.size_type.y, o.size_type.z, o.pos_rounding.w);
  } else if (typeId < 17.5) {
    
    d = sdCutSphere(pTr, o.size_type.x, o.size_type.y);
  } else if (typeId < 18.5) {
    
    d = sdCutHollowSphere(pTr, o.size_type.x, o.size_type.y, o.size_type.z);
  } else if (typeId < 19.5) {
    
    d = sdDeathStar(pTr, o.size_type.x, o.size_type.y, o.size_type.z);
  } else if (typeId < 20.5) {
    
    let angle = o.size_type.x;
    let sc = vec2f(sin(angle), cos(angle));
    d = sdSolidAngle(pTr, sc, o.size_type.y);
  } else if (typeId < 21.5) {
    
    d = sdLink(pTr, o.size_type.y, o.size_type.x, o.size_type.z);
  } else if (typeId > 29.5 && typeId < 32.5) {
    
    
    
    
    
    let isRevolve = (modMask & 0x200u) != 0u;
    let isExtrude = (modMask & 0x100u) != 0u;
    let opParam   = o.modifier2.z;

    
    
    
    
    var p2: vec2f;
    if (isRevolve) {
      p2 = vec2f(length(pTr.xz) - opParam, pTr.y);
    } else {
      p2 = pTr.xy;
    }

    
    var d2 = 1e4;
    if (typeId < 30.5) {
      d2 = sdCircle2D(p2, o.size_type.x);
    } else if (typeId < 31.5) {
      d2 = sdRect2D(p2, o.size_type.xy);
    } else {
      d2 = sdRoundedRect2D(p2, o.size_type.xy, o.pos_rounding.w);
    }

    
    if (isRevolve) {
      
      d = d2;
    } else {
      
      let h = select(0.01, opParam, isExtrude);
      let w = vec2f(d2, abs(pTr.z) - h);
      d = min(max(w.x, w.y), 0.0) + length(max(w, vec2f(0.0)));
    }
  }

  
  
  if ((modMask & 0x40u) != 0u) {
    
    let amp  = o.modifier2.x;
    let freq = o.modifier2.y;
    let bump = sin(freq * pTr.x) * sin(freq * pTr.y) * sin(freq * pTr.z);
    d = d + bump * amp;
  }
  if ((modMask & 0x1u) != 0u) {
    
    d = abs(d) - o.modifier.y;
  }

  return d;
}

fn sceneSDF(p: vec3f, selfIdx: u32, selfDist: f32) -> SDFResult {
  var res = SDFResult(selfDist, selfIdx);
  
  
  
  let gx = i32(floor((p.x + 32.0) * 0.5));
  let gy = i32(floor((p.y + 32.0) * 0.5));
  let gz = i32(floor((p.z + 96.0) * 0.25));

  if (gx >= 0 && gx < 32 && gy >= 0 && gy < 32 && gz >= 0 && gz < 32) {
    let cellIdx = u32(gx) + u32(gy) * 32u + u32(gz) * 32u * 32u;
    let cellCount = min(grid.cells[cellIdx].count, 15u);

    for (var i = 0u; i < cellCount; i++) {
      let iid = grid.cells[cellIdx].indices[i];
      if (iid == selfIdx) { continue; }
      let d = evalObjectSDF(p, iid);
      if (d < res.dist) {
        res.dist = d;
        res.idx = iid;
      }
    }
  } else {
    
    let n = u32(uni.params4.w);
    for (var i = 0u; i < n; i++) {
        if (i == selfIdx) { continue; }
        let d = evalObjectSDF(p, i);
        if (d < res.dist) {
          res.dist = d;
          res.idx = i;
        }
    }
  }
  return res;
}

fn getHeatmap(v: f32) -> vec4f {
  let low  = vec3f(0.0, 0.2, 1.0); 
  let mid  = vec3f(1.0, 1.0, 0.0); 
  let high = vec3f(1.0, 0.0, 0.0); 
  var col = mix(low, mid, smoothstep(0.0, 0.5, v));
  col = mix(col, high, smoothstep(0.5, 1.0, v));
  return vec4f(col, 1.0);
}

fn calcNormal(p: vec3f, i: u32, dSelf: f32) -> vec3f {
  let e = vec2f(0.0001, 0.0);
  return normalize(vec3f(
    evalObjectSDF(p + e.xyy, i) - dSelf,
    evalObjectSDF(p + e.yxy, i) - dSelf,
    evalObjectSDF(p + e.yyx, i) - dSelf
  ));
}

fn unpackColor(u: u32) -> vec4f {
  return vec4f(
    f32((u >> 24u) & 0xFFu) / 255.0,
    f32((u >> 16u) & 0xFFu) / 255.0, 
    f32((u >> 8u) & 0xFFu) / 255.0,
    f32(u & 0xFFu) / 255.0
  );
}

fn unpackPropsA(u: u32) -> vec4f {
  return vec4f(
    f32(u & 0xFFu) / 255.0,         
    f32((u >> 8u) & 0xFFu) / 255.0, 
    f32((u >> 16u) & 0xFFu),        
    f32((u >> 24u) & 0xFFu)         
  );
}

fn unpackPropsB(u: u32) -> vec4f {
  return vec4f(
    f32(u & 0xFFu) / 255.0,           
    f32((u >> 8u) & 0xFFu),           
    f32((u >> 16u) & 0xFFu) / 255.0,  
    f32((u >> 24u) & 0xFFu) / 255.0   
  );
}

fn unpackPropsC(u: u32) -> vec4f {
  return vec4f(
    f32((u >> 8u)  & 0xFFu) / 255.0,  
    f32((u >> 16u) & 0xFFu) / 255.0,  
    f32((u >> 24u) & 0x1u),           
    f32((u >> 25u) & 0x1u)            
  );
}

fn unpackFastAA(u: u32) -> f32 {
  return f32((u >> 26u) & 0x3Fu) / 63.0;
}

struct VertexOutput {
  @builtin(position) pos: vec4f,
  @location(0) worldPos: vec3f,
  @location(1) @interpolate(flat) iid: u32
}

@vertex 
fn vs(@location(0) pos: vec3f, @builtin(instance_index) iid: u32) -> VertexOutput {
  let o = objects[iid];
  
  
  var env = o.size_type.xyz + o.pos_rounding.w;
  
  
  if (o.size_type.w > 0.5 && o.size_type.w < 1.5) { 
    
    env = vec3f(o.size_type.x, o.size_type.y + o.size_type.x, o.size_type.x); 
  } else if (o.size_type.w > 1.5 && o.size_type.w < 2.5) { 
    
    env = o.size_type.xxx; 
  } else if (o.size_type.w > 2.5 && o.size_type.w < 3.5) {
    
    let ra = o.size_type.x;
    let rb = o.size_type.y;
    env = vec3f(ra + rb, rb, ra + rb);
  } else if (o.size_type.w > 3.5 && o.size_type.w < 4.5) {
    
    env = o.size_type.xyz;
  } else if (o.size_type.w > 4.5 && o.size_type.w < 5.5) {
    
    env = vec3f(o.size_type.x, o.size_type.y, o.size_type.x);
  } else if (o.size_type.w > 5.5 && o.size_type.w < 6.5) {
    
    env = vec3f(o.size_type.x, o.size_type.y, o.size_type.x);
  } else if (o.size_type.w > 6.5 && o.size_type.w < 7.5) {
    
    env = vec3f(o.size_type.x, o.size_type.y, o.size_type.x);
  } else if (o.size_type.w > 7.5 && o.size_type.w < 8.5) {
    
    let r = max(o.size_type.x, o.size_type.z);
    env = vec3f(r, o.size_type.y, r);
  } else if (o.size_type.w > 8.5 && o.size_type.w < 9.5) {
    
    env = vec3f(o.size_type.x, o.size_type.y, o.size_type.x);
  } else if (o.size_type.w > 9.5 && o.size_type.w < 10.5) {
    
    env = o.size_type.xxx;
  } else if (o.size_type.w > 10.5 && o.size_type.w < 11.5) {
    
    env = vec3f(o.size_type.x, o.size_type.y, o.size_type.x);
  } else if (o.size_type.w > 11.5 && o.size_type.w < 12.5) {
    
    env = o.size_type.xyz;
  } else if (o.size_type.w > 12.5 && o.size_type.w < 13.5) {
    
    env = vec3f(o.size_type.x, o.size_type.y, o.size_type.x);
  } else if (o.size_type.w > 13.5 && o.size_type.w < 14.5) {
    
    let rmax = max(o.size_type.x, o.size_type.z);
    env = vec3f(rmax, o.size_type.y + rmax, rmax);
  } else if (o.size_type.w > 14.5 && o.size_type.w < 15.5) {
    
    env = o.size_type.xyz + o.pos_rounding.w;
  } else if (o.size_type.w > 15.5 && o.size_type.w < 16.5) {
    
    env = vec3f(o.size_type.x + o.pos_rounding.w, o.size_type.z, o.size_type.y + o.pos_rounding.w);
  } else if (o.size_type.w > 16.5 && o.size_type.w < 17.5) {
    
    env = o.size_type.xxx;
  } else if (o.size_type.w > 17.5 && o.size_type.w < 18.5) {
    
    let r = o.size_type.x + o.size_type.z;
    env = vec3f(r, r, r);
  } else if (o.size_type.w > 18.5 && o.size_type.w < 19.5) {
    
    env = o.size_type.xxx;
  } else if (o.size_type.w > 19.5 && o.size_type.w < 20.5) {
    
    env = vec3f(o.size_type.y, o.size_type.y, o.size_type.y);
  } else if (o.size_type.w > 20.5 && o.size_type.w < 21.5) {
    
    let r1 = o.size_type.x;
    let le = o.size_type.y;
    let r2 = o.size_type.z;
    env = vec3f(r1 + r2, le + r1 + r2, r2);
  } else if (o.size_type.w > 29.5 && o.size_type.w < 32.5) {
    
    
    
    
    var ext2: vec2f;
    if (o.size_type.w < 30.5) {
      ext2 = vec2f(o.size_type.x, o.size_type.x); 
    } else {
      ext2 = o.size_type.xy + o.pos_rounding.w;   
    }
    let mask    = u32(o.modifier.x);
    let isRev   = (mask & 0x200u) != 0u;
    let isExt   = (mask & 0x100u) != 0u;
    let opParam = o.modifier2.z;
    if (isRev) {
      
      
      let r = opParam + ext2.x;
      env = vec3f(r, ext2.y, r);
    } else {
      
      let zh = select(0.01, opParam, isExt);
      env = vec3f(ext2.x, ext2.y, zh);
    }
  }
  
  
  let pB = unpackPropsB(o.material.w);
  let thick = pB.x;

  
  
  
  
  
  
  
  
  
  const GLOW_CUTOFF = 0.05;
  let glowK   = log(max(o.glow_intensity, GLOW_CUTOFF) / GLOW_CUTOFF) * 0.5;
  let glowR   = o.glow_radius * glowK * step(0.01, o.glow_intensity);

  
  
  
  
  
  let fastGlowK = log(max(uni.fastEffectScalars.x, GLOW_CUTOFF) / GLOW_CUTOFF) * 0.5;
  let fastGlowR = uni.fastEffectScalars.y * fastGlowK * step(0.01, uni.fastEffectScalars.x);
  let fastThick     = uni.fastEffectScalars.z;
  let fastActive    = uni.fastEffectScalars.w;
  let totalGlowR    = max(glowR, fastGlowR * fastActive);
  let totalThick    = max(thick, fastThick * fastActive);

  
  
  
  
  
  
  let pAv          = unpackPropsA(o.material.z);
  let isGlassV     = u32(pAv.z) == 7u;
  let modMaskV     = select(u32(o.modifier.x), 0u, isGlassV);
  let onionExpand  = o.modifier.y  * f32((modMaskV & 0x1u)  != 0u);
  
  let displExpand  = o.modifier2.x * f32((modMaskV & 0x40u) != 0u);
  
  
  let bendK        = o.modifier.w;
  let bendExpand   = max(max(env.x, env.y), env.z) * abs(bendK) * 0.5
                       * f32((modMaskV & 0x20u) != 0u);
  
  let elongExpand  = o.modifier3.xyz * f32((modMaskV & 0x80u) != 0u);

  let scalarExpand = totalThick + totalGlowR + onionExpand + displExpand + bendExpand;

  let margin = 1.00; 
  let wPos = rotateXYZ(
      pos * (env + elongExpand + vec3f(scalarExpand)) * 2.02 * margin,
      o.rotation.xyz
    ) + o.pos_rounding.xyz;
  
  var out: VertexOutput;
  out.pos = uni.vpMatrix * vec4f(wPos, 1.0);
  out.worldPos = wPos;
  out.iid = iid;
  return out;
}

@fragment
fn fs(i: VertexOutput) -> @location(0) vec4f {
  let ro = uni.cameraPos.xyz;
  let rd = normalize(i.worldPos - ro);
  let tF = tan(uni.params1.x * 0.5 * 3.14159 / 180.0);
  let o  = objects[i.iid];

  
  
  
  
  
  
  
  
  let isSimple = ((o.material.w & 0xFFu) == 0u) && (o.glow_intensity <= 0.0);

  var t = 0.01;
  var minDist = 1e4;
  var minT    = 0.0;

  var minDistGlobal = 1e4;
  var minIdxGlobal  = 0u;
  var minDistOutline = 1e4;
  var minIdxOutline  = 0u;
  var hasOcclusion  = false;
  var occlusionT    = 1e4;

  let baseEps = uni.extraParams.x;
  let maxS    = i32(uni.extraParams.y);
  let lodK    = uni.perfParams.x;  
  let stepK   = uni.perfParams.z;  

  
  for (var j = 0; j < maxS; j++) {
    let p = ro + rd * t;

    
    
    
    let eps = baseEps * (1.0 + t * lodK);

    
    let dSelf = evalObjectSDF(p, i.iid);
    if (t > 150.0) { break; }

    
    
    var stepDist = dSelf;

    if (!isSimple) {
      
      let gRes = sceneSDF(p, i.iid, dSelf);

      
      if (gRes.dist > 2.0 && t < 100.0) {
        t += gRes.dist * 0.9;
        continue;
      }

      let gO   = objects[gRes.idx];
      let gA   = unpackColor(gO.material.x).a;

      if (dSelf < minDist) {
        minDist = dSelf;
        minT = t;
      }

      
      if (gRes.dist < minDistGlobal && (gA > 0.1 || gRes.idx == i.iid)) {
        minDistGlobal = gRes.dist;
        minIdxGlobal = gRes.idx;
      }

      
      
      let gThick = unpackPropsB(gO.material.w).x;
      if (gRes.dist < minDistOutline && (gRes.dist < gThick || gRes.idx == i.iid)) {
        minDistOutline = gRes.dist;
        minIdxOutline = gRes.idx;
      }

      
      
      if (gRes.dist < eps && gRes.idx != i.iid && gA > 0.95) {
        hasOcclusion = true;
        occlusionT = t;
        break;
      }

      stepDist = gRes.dist;
    }

    
    if (dSelf < eps) {
      if (uni.extraParams.z > 0.5) { return getHeatmap(f32(j) / f32(maxS)); }

      let n = calcNormal(p, i.iid, dSelf);

      let mainColor = unpackColor(o.material.x);
      let outColor  = unpackColor(o.material.y);
      let hColor    = unpackColor(o.hColor);
      let pA = unpackPropsA(o.material.z);
      let pB = unpackPropsB(o.material.w);
      let pC = unpackPropsC(o.packed_reserved);

      let ambient        = pA.x;
      let smoothness     = pA.y;
      let shaderId       = u32(pA.z);
      let steps          = pA.w;
      let thickness      = pB.x;
      let shininess      = pB.y;
      let roughness      = pB.z;
      let roughnessScale = pB.w;
      let grain          = pC.x;
      let grainScale     = pC.y;
      let grainType      = u32(pC.z);

      
      
      let p_obj = rotateZYX(p - o.pos_rounding.xyz, -o.rotation.xyz);
      let n_obj = rotateZYX(n, -o.rotation.xyz);

      
      
      
      
      var bumped_n = n;
      if (roughness > 0.0) {
        let freq = 1.0 + roughnessScale * 127.0;
        let b0 = noise3D(p_obj * freq);
        let eps2 = 0.01;
        let b1 = noise3D((p_obj + vec3f(eps2, 0.0, 0.0)) * freq);
        let b2 = noise3D((p_obj + vec3f(0.0, eps2, 0.0)) * freq);
        let b3 = noise3D((p_obj + vec3f(0.0, 0.0, eps2)) * freq);
        let bump_grad = (vec3f(b1, b2, b3) - b0) / eps2;
        bumped_n = normalize(n + rotateXYZ(bump_grad * roughness * 0.5, o.rotation.xyz));
      }

      let lightDir = normalize(vec3f(1.0, 2.0, 3.0));
      let viewDir  = normalize(uni.cameraPos.xyz - p);
      let edge     = max(dot(bumped_n, viewDir), 0.0);
      let diff     = max(dot(bumped_n, lightDir), 0.0);

      var color    = mainColor.rgb * max(diff, ambient);

      

      
      if (shaderId == 1u) {
        let halfDir = normalize(lightDir + viewDir);
let spec = pow(max(dot(bumped_n, halfDir), 0.0), shininess);
color += vec3f(spec * 0.5) * hColor.rgb;
      }

      
      if (shaderId == 2u) {
        let tSteps = max(steps, 1.0);
let val = diff * tSteps;
let toonDiff = (floor(val) + smoothstep(0.0, max(smoothness, 0.01), fract(val))) / tSteps;
color = mainColor.rgb * max(toonDiff, ambient);
      }

      
      if (shaderId == 3u) {
        let fresnel = pow(1.0 - edge, max(shininess, 1.0));
let glow = hColor.rgb * fresnel; 
color += glow;
      }

      
      if (shaderId == 4u) {
        let m = 2.0 * sqrt(pow(bumped_n.x, 2.0) + pow(bumped_n.y, 2.0) + pow(bumped_n.z + 1.0, 2.0));
let muv = bumped_n.xy / m + 0.5;
let f1 = smoothstep(0.4, 0.6, muv.y);
let f2 = smoothstep(0.7, 0.9, muv.y);
let matColor = mix(hColor.rgb, mainColor.rgb, f1) + vec3f(f2 * 0.8 * (shininess / 32.0));
color = matColor;
      }

      
      if (shaderId == 6u) {
        var tangent_local: vec3f;
if (abs(o.size_type.w - 3.0) < 0.1) { 
  tangent_local = normalize(vec3f(-p_obj.z, 0.0, p_obj.x));
} else {
  tangent_local = normalize(cross(n_obj, vec3f(0.0, 1.0, 0.0)));
  if (abs(dot(n_obj, vec3f(0.0, 1.0, 0.0))) > 0.99) {
    tangent_local = normalize(cross(n_obj, vec3f(1.0, 0.0, 0.0)));
  }
}

var grainVal = 1.0;
if (grain > 0.0) {
  let gFreq = (1.0 + grainScale * 63.0) * 15.0;
  var gRes = 1.0;

  if (grainType == 1u) { 
    gRes = noise3D(p_obj * gFreq);
  } else { 
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    var gCoord: vec2f;
    if (abs(o.size_type.w - 3.0) < 0.1) {
      
      
      
      gCoord = vec2f(length(p_obj.xz), p_obj.y) * gFreq;
    } else {
      let brushDir = vec3f(0.0, 1.0, 0.0);
      var brushOnSurface = brushDir - n_obj * dot(n_obj, brushDir);
      if (dot(brushOnSurface, brushOnSurface) < 0.01) {
        
        let alt = vec3f(1.0, 0.0, 0.0);
        brushOnSurface = alt - n_obj * dot(n_obj, alt);
      }
      brushOnSurface = normalize(brushOnSurface);
      let brushPerp = cross(n_obj, brushOnSurface);
      
      
      gCoord = vec2f(dot(p_obj, brushPerp), dot(p_obj, brushOnSurface) * 0.01) * gFreq;
    }
    gRes = noise2D(gCoord);
  }

  let sharpG = pow(gRes, 4.0);
  grainVal = 1.0 - (sharpG * grain * 40.0);
}

let tangent = rotateXYZ(tangent_local, o.rotation.xyz);
let halfDir_ani = normalize(lightDir + viewDir);
let dotBNH = max(dot(bumped_n, halfDir_ani), 0.0);
let dotTH = dot(tangent, halfDir_ani);

let sinTH = sqrt(max(0.0, 1.0 - dotTH * dotTH));
let anisotropicSpec = pow(sinTH, max(shininess * 0.5, 1.0)) * smoothness;
let isotropicSpec = pow(dotBNH, max(shininess, 1.0)) * (1.0 - smoothness);

let metallicDiff = mix(max(diff, ambient), ambient, smoothness * 0.6);
color = mainColor.rgb * metallicDiff * grainVal;

let fresnel_aniso = pow(1.0 - edge, 3.0);
color += hColor.rgb * (anisotropicSpec + isotropicSpec + fresnel_aniso * 0.5) * grainVal;
      }

      
      if (thickness > 0.0) {
        let rimEdge = max(dot(n, viewDir), 0.0);
        let innerRim = 1.0 - smoothstep(0.0, thickness * 0.5, rimEdge);
        color = mix(color, outColor.rgb, innerRim * outColor.a);
      }

      
      return vec4f(color * mainColor.a, mainColor.a);
    }

    
    
    
    
    t += max(stepDist, eps * 2.0) * stepK;
    if (t > 50.0) { break; }

    
    if (uni.extraParams.z > 0.5 && j == maxS - 1) {
        return vec4f(0.0, 0.0, 0.0, 0.2); 
    }
  }

  if (uni.extraParams.z > 0.5) {
      return vec4f(0.0, 0.0, 0.0, 0.2); 
  }

  
  
  if (isSimple) {
    discard;
    return vec4f(0.0);
  }

  

  
  let pB = unpackPropsB(o.material.w);
  let pC = unpackPropsC(o.packed_reserved);
  let thick = pB.x;

  
  
  let isOccluded = hasOcclusion && (occlusionT < minT - 0.01);

  
  var glowRGB = vec3f(0.0);
  var glowA   = 0.0;
  let gIntensity = o.glow_intensity;
  let gRadius    = max(o.glow_radius, 0.01);
  if (gIntensity > 0.0 && !isOccluded) {
      let gColor = unpackColor(o.glow_color);
      let falloff = 1.0 / (gRadius * 0.5);
      let glowFactor = gIntensity * exp(-minDist * falloff);
      
      glowA   = clamp(glowFactor, 0.0, 1.0) * gColor.a;
      glowRGB = gColor.rgb * glowA; 
  }

  
  var shellRGB = vec3f(0.0);
  var shellA   = 0.0;
  
  
  let noMerge = pC.w > 0.5;
  if (thick > 0.0 && minDist < thick && (noMerge || minIdxOutline == i.iid) && !isOccluded) {
      let oc = unpackColor(o.material.y);
      shellRGB = oc.rgb;
      shellA   = oc.a * smoothstep(thick, thick * 0.8, minDist);
  }

  
  let glowMask = 1.0 - shellA;
  glowA   *= glowMask;
  glowRGB *= glowMask;

  
  
  
  let viewport_height = uni.pointerAndViewport.w;
  let pixel_size = tF * minT / (viewport_height * 0.5) * uni.perfParams.y;
  if (minDist < pixel_size && minIdxGlobal == i.iid && !isOccluded) {
    let n = calcNormal(ro + rd * minT, i.iid, minDist);
    let diff = max(dot(n, normalize(vec3f(1.0, 2.0, 3.0))), 0.2);
    let mColor = unpackColor(o.material.x);
    
    let surfRGB = mColor.rgb * diff;
    let surfA   = mColor.a * clamp(1.0 - minDist / pixel_size, 0.0, 1.0);
    
    
    let resRGB = surfRGB * surfA + (shellRGB * shellA + glowRGB) * (1.0 - surfA);
    let resA   = clamp(surfA + shellA * (1.0 - surfA) + glowA, 0.0, 1.0);

    return vec4f(resRGB, resA);
  }

  
  let finalRGB = shellRGB * shellA + glowRGB;
  let finalA   = clamp(shellA + glowA, 0.0, 1.0);

  if (finalA > 0.001) {
    return vec4f(finalRGB, finalA);
  }

  discard;
  return vec4f(0.0);
}

struct FastFragOutput {
  @location(0)          color: vec4f,
  @builtin(frag_depth)  depth: f32,
}

@fragment
fn fs_fast(i: VertexOutput) -> FastFragOutput {
  let ro = uni.cameraPos.xyz;
  let rd = normalize(i.worldPos - ro);
  let tF = tan(uni.params1.x * 0.5 * 3.14159 / 180.0);
  let o  = objects[i.iid];

  var t = 0.01;
  var minDist = 1e4;
  var minT    = 0.0;

  let baseEps = uni.extraParams.x;
  let maxS    = i32(uni.extraParams.y);
  let lodK    = uni.perfParams.x;
  let stepK   = uni.perfParams.z;

  
  for (var j = 0; j < maxS; j++) {
    let p = ro + rd * t;
    let eps = baseEps * (1.0 + t * lodK);
    let dSelf = evalObjectSDF(p, i.iid);
    if (t > 150.0) { break; }

    if (dSelf < minDist) {
      minDist = dSelf;
      minT    = t;
    }

    if (dSelf < eps) {
      
      if (uni.extraParams.z > 0.5) {
        let clipPos = uni.vpMatrix * vec4f(p, 1.0);
        return FastFragOutput(getHeatmap(f32(j) / f32(maxS)), clipPos.z / clipPos.w);
      }

      let n = calcNormal(p, i.iid, dSelf);

      
      
      
      let mainColor = unpackColor(o.material.x);
      let hColor    = unpackColor(o.hColor);
      let pA = unpackPropsA(o.material.z);
      let pB = unpackPropsB(o.material.w);
      let pC = unpackPropsC(o.packed_reserved);

      let ambient        = pA.x;
      let smoothness     = pA.y;
      let shaderId       = u32(pA.z);
      let steps          = pA.w;
      let shininess      = pB.y;
      let roughness      = pB.z;
      let roughnessScale = pB.w;
      let grain          = pC.x;
      let grainScale     = pC.y;
      let grainType      = u32(pC.z);

      let p_obj = rotateZYX(p - o.pos_rounding.xyz, -o.rotation.xyz);
      let n_obj = rotateZYX(n, -o.rotation.xyz);

      
      var bumped_n = n;
      if (roughness > 0.0) {
        let freq = 1.0 + roughnessScale * 127.0;
        let b0 = noise3D(p_obj * freq);
        let eps2 = 0.01;
        let b1 = noise3D((p_obj + vec3f(eps2, 0.0, 0.0)) * freq);
        let b2 = noise3D((p_obj + vec3f(0.0, eps2, 0.0)) * freq);
        let b3 = noise3D((p_obj + vec3f(0.0, 0.0, eps2)) * freq);
        let bump_grad = (vec3f(b1, b2, b3) - b0) / eps2;
        bumped_n = normalize(n + rotateXYZ(bump_grad * roughness * 0.5, o.rotation.xyz));
      }

      let lightDir = normalize(vec3f(1.0, 2.0, 3.0));
      let viewDir  = normalize(uni.cameraPos.xyz - p);
      let edge     = max(dot(bumped_n, viewDir), 0.0);
      let diff     = max(dot(bumped_n, lightDir), 0.0);

      var color = mainColor.rgb * max(diff, ambient);

      
      if (shaderId == 1u) {
        let halfDir = normalize(lightDir + viewDir);
let spec = pow(max(dot(bumped_n, halfDir), 0.0), shininess);
color += vec3f(spec * 0.5) * hColor.rgb;
      }
      if (shaderId == 2u) {
        let tSteps = max(steps, 1.0);
let val = diff * tSteps;
let toonDiff = (floor(val) + smoothstep(0.0, max(smoothness, 0.01), fract(val))) / tSteps;
color = mainColor.rgb * max(toonDiff, ambient);
      }
      if (shaderId == 3u) {
        let fresnel = pow(1.0 - edge, max(shininess, 1.0));
let glow = hColor.rgb * fresnel; 
color += glow;
      }
      if (shaderId == 4u) {
        let m = 2.0 * sqrt(pow(bumped_n.x, 2.0) + pow(bumped_n.y, 2.0) + pow(bumped_n.z + 1.0, 2.0));
let muv = bumped_n.xy / m + 0.5;
let f1 = smoothstep(0.4, 0.6, muv.y);
let f2 = smoothstep(0.7, 0.9, muv.y);
let matColor = mix(hColor.rgb, mainColor.rgb, f1) + vec3f(f2 * 0.8 * (shininess / 32.0));
color = matColor;
      }
      if (shaderId == 6u) {
        var tangent_local: vec3f;
if (abs(o.size_type.w - 3.0) < 0.1) { 
  tangent_local = normalize(vec3f(-p_obj.z, 0.0, p_obj.x));
} else {
  tangent_local = normalize(cross(n_obj, vec3f(0.0, 1.0, 0.0)));
  if (abs(dot(n_obj, vec3f(0.0, 1.0, 0.0))) > 0.99) {
    tangent_local = normalize(cross(n_obj, vec3f(1.0, 0.0, 0.0)));
  }
}

var grainVal = 1.0;
if (grain > 0.0) {
  let gFreq = (1.0 + grainScale * 63.0) * 15.0;
  var gRes = 1.0;

  if (grainType == 1u) { 
    gRes = noise3D(p_obj * gFreq);
  } else { 
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    var gCoord: vec2f;
    if (abs(o.size_type.w - 3.0) < 0.1) {
      
      
      
      gCoord = vec2f(length(p_obj.xz), p_obj.y) * gFreq;
    } else {
      let brushDir = vec3f(0.0, 1.0, 0.0);
      var brushOnSurface = brushDir - n_obj * dot(n_obj, brushDir);
      if (dot(brushOnSurface, brushOnSurface) < 0.01) {
        
        let alt = vec3f(1.0, 0.0, 0.0);
        brushOnSurface = alt - n_obj * dot(n_obj, alt);
      }
      brushOnSurface = normalize(brushOnSurface);
      let brushPerp = cross(n_obj, brushOnSurface);
      
      
      gCoord = vec2f(dot(p_obj, brushPerp), dot(p_obj, brushOnSurface) * 0.01) * gFreq;
    }
    gRes = noise2D(gCoord);
  }

  let sharpG = pow(gRes, 4.0);
  grainVal = 1.0 - (sharpG * grain * 40.0);
}

let tangent = rotateXYZ(tangent_local, o.rotation.xyz);
let halfDir_ani = normalize(lightDir + viewDir);
let dotBNH = max(dot(bumped_n, halfDir_ani), 0.0);
let dotTH = dot(tangent, halfDir_ani);

let sinTH = sqrt(max(0.0, 1.0 - dotTH * dotTH));
let anisotropicSpec = pow(sinTH, max(shininess * 0.5, 1.0)) * smoothness;
let isotropicSpec = pow(dotBNH, max(shininess, 1.0)) * (1.0 - smoothness);

let metallicDiff = mix(max(diff, ambient), ambient, smoothness * 0.6);
color = mainColor.rgb * metallicDiff * grainVal;

let fresnel_aniso = pow(1.0 - edge, 3.0);
color += hColor.rgb * (anisotropicSpec + isotropicSpec + fresnel_aniso * 0.5) * grainVal;
      }

      let clipPos = uni.vpMatrix * vec4f(p, 1.0);
      return FastFragOutput(vec4f(color * mainColor.a, mainColor.a), clipPos.z / clipPos.w);
    }

    t += max(dSelf, eps * 2.0) * stepK;
    if (t > 50.0) { break; }
  }

  
  
  
  
  
  if (uni.extraParams.z > 0.5) {
    let clipPos = uni.vpMatrix * vec4f(ro + rd * minT, 1.0);
    return FastFragOutput(vec4f(0.0, 0.0, 0.0, 0.2), clipPos.z / clipPos.w);
  }

  
  
  
  
  
  
  let fastAA = unpackFastAA(o.packed_reserved);
  if (fastAA > 0.0 && minT > 0.001) {
    let viewport_height = uni.pointerAndViewport.w;
    
    
    let pixel_size = tF * minT / (viewport_height * 0.5) * fastAA * uni.perfParams.y;
    if (minDist < pixel_size) {
      let p = ro + rd * minT;
      let n = calcNormal(p, i.iid, minDist);
      let lightDir = normalize(vec3f(1.0, 2.0, 3.0));
      let diff     = max(dot(n, lightDir), 0.2);
      let mColor   = unpackColor(o.material.x);
      let surfA    = mColor.a * clamp(1.0 - minDist / pixel_size, 0.0, 1.0);
      let clipPos  = uni.vpMatrix * vec4f(p, 1.0);
      return FastFragOutput(
        vec4f(mColor.rgb * diff * surfA, surfA),
        clipPos.z / clipPos.w
      );
    }
  }

  discard;
  return FastFragOutput(vec4f(0.0), 1.0);
}

@fragment
fn fs_fast_effect(i: VertexOutput) -> @location(0) vec4f {
  let ro = uni.cameraPos.xyz;
  let rd = normalize(i.worldPos - ro);

  var t = 0.01;
  var minDist = 1e4;

  let baseEps = uni.extraParams.x;
  let maxS    = i32(uni.extraParams.y);
  let lodK    = uni.perfParams.x;
  let stepK   = uni.perfParams.z;

  
  for (var j = 0; j < maxS; j++) {
    let p = ro + rd * t;
    let eps = baseEps * (1.0 + t * lodK);
    let dSelf = evalObjectSDF(p, i.iid);
    if (t > 150.0) { break; }

    if (dSelf < minDist) { minDist = dSelf; }
    if (dSelf < eps) { discard; }   

    t += max(dSelf, eps * 2.0) * stepK;
    if (t > 50.0) { break; }
  }

  
  
  
  var color = vec3f(0.0);
  var alpha = 0.0;

  
  let outlineThick = uni.fastEffectScalars.z;
  if (outlineThick > 0.0 && minDist < outlineThick) {
    let oc = uni.fastEffectOutline;
    let shellA = oc.a * smoothstep(outlineThick, outlineThick * 0.8, minDist);
    color = oc.rgb * shellA;
    alpha = shellA;
  }

  
  let glowIntensity = uni.fastEffectScalars.x;
  if (glowIntensity > 0.0) {
    let gColor   = uni.fastEffectGlow;
    let gRadius  = max(uni.fastEffectScalars.y, 0.01);
    let falloff  = 1.0 / (gRadius * 0.5);
    let gFactor  = glowIntensity * exp(-minDist * falloff);
    let glowA    = clamp(gFactor, 0.0, 1.0) * gColor.a;
    let glowMask = 1.0 - alpha;
    color += gColor.rgb * glowA * glowMask;
    alpha = clamp(alpha + glowA * glowMask, 0.0, 1.0);
  }

  if (alpha < 0.001) { discard; }
  return vec4f(color, alpha);
}

@group(1) @binding(0) var bgTex:         texture_2d<f32>;
@group(1) @binding(1) var bgSampler:     sampler;

@group(1) @binding(2) var reflectionTex: texture_2d<f32>;

@fragment
fn fs_refract(i: VertexOutput) -> FastFragOutput {
  let ro = uni.cameraPos.xyz;
  let rd = normalize(i.worldPos - ro);
  let tF = tan(uni.params1.x * 0.5 * 3.14159 / 180.0);
  let o  = objects[i.iid];

  var t = 0.01;
  
  
  
  var minDist = 1e4;
  var minT    = 0.0;

  let baseEps = uni.extraParams.x;
  let maxS    = i32(uni.extraParams.y);
  let lodK    = uni.perfParams.x;
  let stepK   = uni.perfParams.z;

  
  for (var j = 0; j < maxS; j++) {
    let p = ro + rd * t;
    let eps = baseEps * (1.0 + t * lodK);
    let dSelf = evalObjectSDF(p, i.iid);
    if (dSelf < minDist) { minDist = dSelf; minT = t; }
    if (t > 150.0) { break; }

    if (dSelf < eps) {
      
      var n = calcNormal(p, i.iid, dSelf);

      
      let grainAmt = clamp(o.modifier4.z, 0.0, 1.0);
      if (grainAmt > 0.0) {
        let freq = 400.0 + max(o.modifier4.w, 0.0) * 6.0;
        let eps2 = 1.0 / freq;
        let b0 = noise3D(p * freq);
        let b1 = noise3D((p + vec3f(eps2, 0.0, 0.0)) * freq);
        let b2 = noise3D((p + vec3f(0.0, eps2, 0.0)) * freq);
        let b3 = noise3D((p + vec3f(0.0, 0.0, eps2)) * freq);
        let bump_grad = (vec3f(b1, b2, b3) - b0) / eps2;
        n = normalize(n + bump_grad * grainAmt * 0.00025);
      }
      

      let mainColor = unpackColor(o.material.x);
      let pB = unpackPropsB(o.material.w);
      
      
      
      let thickness = o.modifier3.w;
      
      
      
      
      let ior       = o.modifier.x;
      let eta       = 1.0 / max(ior, 1.0001);

      
      let refractedIn = refract(rd, n, eta);
      let refValid    = dot(refractedIn, refractedIn) > 0.0001;

      
      
      
      let pcSurf  = uni.vpMatrix * vec4f(p, 1.0);
      let surfNDC = pcSurf.xy / pcSurf.w;
      var bgUV    = vec2f(surfNDC.x * 0.5 + 0.5, surfNDC.y * -0.5 + 0.5);

      
      
      
      var travelDist = 0.0;

      if (refValid) {
        
        
        
        
        
        
        
        
        var pIn:      vec3f;
        var nBack:    vec3f;
        var marched:  bool;

        let typeId   = o.size_type.w;
        let isSphere = typeId > 1.5 && typeId < 2.5;

        if (isSphere) {
          
          
          
          let center = o.pos_rounding.xyz;
          let radius = o.size_type.x;
          let oc     = p - center;
          let bH     = dot(refractedIn, oc);
          let c0     = dot(oc, oc) - radius * radius;
          let disc   = bH * bH - c0;
          if (disc > 0.0) {
            let tExit = -bH + sqrt(disc);
            pIn       = p + refractedIn * tExit;
            travelDist = tExit;
            
            
            nBack     = (center - pIn) / radius;
            marched   = true;
          } else {
            
            pIn = p; nBack = -n; marched = false;
          }
        } else {
          
          
          pIn          = p + refractedIn * (eps * 2.0);
          var dIn      = -1.0;
          marched      = false;
          let innerSteps = i32(clamp(o.modifier.z, 1.0, 40.0));
          for (var k = 0; k < innerSteps; k++) {
            dIn = evalObjectSDF(pIn, i.iid);
            if (dIn > eps) { marched = true; break; }
            pIn = pIn + refractedIn * max(abs(dIn) * 0.9, eps * 2.0);
          }
          travelDist = length(pIn - p);
          nBack = -calcNormal(pIn, i.iid, dIn);
        }

        
        
        
        
        
        
        
        
        
        
        if (marched) {
          let refractedOut = refract(refractedIn, nBack, ior);
          let exitValid    = dot(refractedOut, refractedOut) > 0.0001;
          if (exitValid) {
            let pcExit  = uni.vpMatrix * vec4f(pIn + refractedOut * thickness, 1.0);
            let exitNDC = pcExit.xy / pcExit.w;
            bgUV        = vec2f(exitNDC.x * 0.5 + 0.5, exitNDC.y * -0.5 + 0.5);
          }
        }
      }

      
      
      
      
      var distOffset = vec2f(0.0);
      let distMag = o.glow_radius;
      if (distMag > 0.0) {
        let distScale = max(bitcast<f32>(o.packed_reserved), 0.0001) * 0.5;
        
        
        let tShift = o.modifier7.z * uni.bgParams.y;
        let nx = noise3D(p * distScale + vec3f(tShift, 0.0, 0.0));
        let ny = noise3D(p * distScale + vec3f(0.0, tShift, 100.0));
        distOffset = vec2f(nx - 0.5, ny - 0.5) * distMag * 0.05;
        bgUV = bgUV + distOffset;
      }
      

      
      
      bgUV = clamp(bgUV, vec2f(0.001), vec2f(0.999));

      let pageBg   = o.modifier2.rgb;     
      let caAmount = o.modifier.w;
      let blur     = pB.z;
      let lodLevel = blur * 5.0;          

      
      var uvR = bgUV;
      var uvG = bgUV;
      var uvB = bgUV;

      
      let caShift  = (bgUV - vec2f(surfNDC.x * 0.5 + 0.5, surfNDC.y * -0.5 + 0.5)) * caAmount;
      uvR = clamp(bgUV - caShift, vec2f(0.001), vec2f(0.999));
      uvG = clamp(bgUV,           vec2f(0.001), vec2f(0.999));
      uvB = clamp(bgUV + caShift, vec2f(0.001), vec2f(0.999));
      

      
      
      
      var bgR: vec4f;
      var bgG: vec4f;
      var bgB: vec4f;

      
      
      
      
      let aniBits = o.hColor;
      let aniS    = f32(aniBits & 0xFFFFu) / 65535.0;
      let aniR    = f32(aniBits >> 16u) / 65535.0 * 6.2831853;
      let aniBlur = clamp(o.modifier4.y, 0.0, 1.0);
      let aniDir  = vec2f(cos(aniR), sin(aniR)) * aniS * 0.015;
      let aniLod  = clamp(lodLevel + aniS * 1.5 + aniBlur * 3.0, 0.0, 5.0);
      bgR = textureSampleLevel(bgTex, bgSampler, uvR - aniDir * 2.0, aniLod) * 0.0625
          + textureSampleLevel(bgTex, bgSampler, uvR - aniDir,       aniLod) * 0.25
          + textureSampleLevel(bgTex, bgSampler, uvR,                aniLod) * 0.375
          + textureSampleLevel(bgTex, bgSampler, uvR + aniDir,       aniLod) * 0.25
          + textureSampleLevel(bgTex, bgSampler, uvR + aniDir * 2.0, aniLod) * 0.0625;
      bgG = textureSampleLevel(bgTex, bgSampler, uvG - aniDir * 2.0, aniLod) * 0.0625
          + textureSampleLevel(bgTex, bgSampler, uvG - aniDir,       aniLod) * 0.25
          + textureSampleLevel(bgTex, bgSampler, uvG,                aniLod) * 0.375
          + textureSampleLevel(bgTex, bgSampler, uvG + aniDir,       aniLod) * 0.25
          + textureSampleLevel(bgTex, bgSampler, uvG + aniDir * 2.0, aniLod) * 0.0625;
      bgB = textureSampleLevel(bgTex, bgSampler, uvB - aniDir * 2.0, aniLod) * 0.0625
          + textureSampleLevel(bgTex, bgSampler, uvB - aniDir,       aniLod) * 0.25
          + textureSampleLevel(bgTex, bgSampler, uvB,                aniLod) * 0.375
          + textureSampleLevel(bgTex, bgSampler, uvB + aniDir,       aniLod) * 0.25
          + textureSampleLevel(bgTex, bgSampler, uvB + aniDir * 2.0, aniLod) * 0.0625;
      

      
      bgR = textureSampleLevel(bgTex, bgSampler, uvR, lodLevel);
      bgG = textureSampleLevel(bgTex, bgSampler, uvG, lodLevel);
      bgB = textureSampleLevel(bgTex, bgSampler, uvB, lodLevel);
      
      
      
      
      var bgRgb = vec3f(
        bgR.r + pageBg.r * (1.0 - bgR.a),
        bgG.g + pageBg.g * (1.0 - bgG.a),
        bgB.b + pageBg.b * (1.0 - bgB.a),
      );

      
      let attenColor = unpackColor(o.glow_color);
      let attenDist  = max(o.glow_intensity, 0.0001);
      let attenRgb   = clamp(attenColor.rgb, vec3f(0.0001), vec3f(1.0));
      let absorption = -log(attenRgb) / attenDist;
      let transmit   = exp(-absorption * travelDist);
      bgRgb = bgRgb * transmit;
      

      
      
      let viewDir = -rd;
      let NdotV   = max(dot(n, viewDir), 0.0);

      
      
      
      let iridS = clamp(o.modifier5.x, 0.0, 1.0);
      if (iridS > 0.0) {
        let iridFilmIor = 1.3;
        let iridThick   = max(o.modifier5.y, 1.0);
        let iridCos     = sqrt(max(1.0 - (1.0 - NdotV * NdotV) / (iridFilmIor * iridFilmIor), 0.0));
        let iridOPD     = 2.0 * iridFilmIor * iridThick * iridCos;
        let iridR       = cos(6.2831853 * iridOPD / 650.0);
        let iridG       = cos(6.2831853 * iridOPD / 550.0);
        let iridB       = cos(6.2831853 * iridOPD / 450.0);
        let iridCol     = vec3f(iridR, iridG, iridB) * 0.5 + 0.5;
        bgRgb = mix(bgRgb, bgRgb * iridCol, iridS);
      }
      

      
      let metalness = clamp(o.modifier4.x, 0.0, 1.0);
      if (metalness > 0.0) {
        let iorF0    = pow((ior - 1.0) / (ior + 1.0), 2.0);
        let viewFres = iorF0 + (1.0 - iorF0) * pow(1.0 - NdotV, 5.0);
        let metalCol = attenRgb * (0.35 + 0.65 * viewFres);
        bgRgb = mix(bgRgb, metalCol, metalness);
      }
      

      
      
      
      
      
      
      
      let refl = clamp(o.modifier7.x * uni.bgParams.x, 0.0, 1.0);
      if (refl > 0.0) {
        let reflRough  = clamp(o.modifier7.y, 0.0, 1.0);
        let reflDir    = reflect(rd, n);
        let pcRefl     = uni.vpMatrix * vec4f(p + reflDir * 1.0, 1.0);
        let reflNDC    = pcRefl.xy / max(pcRefl.w, 0.001);
        
        
        let reflUV     = clamp(vec2f(reflNDC.x * 0.5 + 0.5, reflNDC.y * -0.5 + 0.5) + distOffset,
                               vec2f(0.001), vec2f(0.999));
        
        
        let reflLOD    = clamp(reflRough * 5.0, 0.0, 5.0);
        let reflSample = textureSampleLevel(reflectionTex, bgSampler, reflUV, reflLOD);
        
        
        
        bgRgb          = mix(bgRgb, reflSample.rgb, refl * reflSample.a);
      }
      

      
      
      
      
      
      
      let cc = clamp(o.modifier5.z, 0.0, 1.0);
      if (cc > 0.0) {
        let ccRough = clamp(o.modifier5.w, 0.0, 1.0);
        let ccExp   = mix(5.0, 1.0, ccRough);
        let ccF0    = 0.04;
        let ccFres  = ccF0 + (1.0 - ccF0) * pow(1.0 - NdotV, ccExp);
        bgRgb       = bgRgb + vec3f(ccFres * cc);
      }
      

      
      
      
      
      let glossK = clamp(o.modifier8.x, 0.0, 1.0);
      if (glossK > 0.0) {
        let R = reflect(rd, n);
        let yR         = clamp(R.y, -1.0, 1.0);
        let env_sky    = vec3f(1.00, 1.02, 1.08);
        let env_mid    = vec3f(0.50, 0.50, 0.52);
        let env_ground = vec3f(0.02, 0.02, 0.04);
        let above   = mix(env_mid, env_sky,    pow(max(yR,  0.0), 0.5));
        let below   = mix(env_mid, env_ground, pow(max(-yR, 0.0), 0.7));
        let envBase = select(below, above, yR >= 0.0);
        let bulbExp = mix(4.0, 256.0, clamp(o.modifier8.y, 0.0, 1.0));
        let bulb1   = pow(max(dot(R, normalize(vec3f( 0.45, 0.85,  0.30))), 0.0), bulbExp) * 4.0;
        let bulb2   = pow(max(dot(R, normalize(vec3f(-0.55, 0.40, -0.40))), 0.0), bulbExp) * 2.5;
        let envCol  = envBase + vec3f(bulb1 + bulb2);
        let coverage = clamp(o.modifier8.z, 0.0, 1.0);
        let glossF   = coverage + (1.0 - coverage) * pow(1.0 - NdotV, 5.0);
        bgRgb        = mix(bgRgb, envCol, glossK * glossF);
      }
      

      
      
      
      
      let sheenK = clamp(o.modifier6.x, 0.0, 1.0);
      if (sheenK > 0.0) {
        let sheenCol = o.modifier6.yzw;
        let sheenF   = pow(1.0 - NdotV, 2.0);
        bgRgb        = bgRgb + sheenCol * (sheenF * sheenK);
      }
      

      
      
      
      
      
      
      let fresBase   = pow(1.0 - NdotV, 5.0) * o.modifier.y;
      
      
      
      let fresnelCol = o.modifier3.rgb;

      let tint    = mainColor.rgb;
      let tintMix = mainColor.a;

      
      
      var rgb = mix(bgRgb, bgRgb * tint, tintMix);
      rgb     = mix(rgb, fresnelCol, clamp(fresBase, 0.0, 1.0));

      
      
      
      
      
      
      let outline = o.modifier2.w;
      let edgeT   = 1.0 - NdotV;
      let OUTLINE_FALLOFF = 8.0;
      let outlineMask = pow(edgeT, OUTLINE_FALLOFF) * outline;
      rgb = mix(rgb, vec3f(0.0), clamp(outlineMask, 0.0, 1.0));
      

      let clipPos = uni.vpMatrix * vec4f(p, 1.0);
      return FastFragOutput(vec4f(rgb, 1.0), clipPos.z / clipPos.w);
    }

    t += max(dSelf, eps * 2.0) * stepK;
    if (t > 50.0) { break; }
  }

  
  
  
  
  
  
  
  
  let viewport_height = uni.pointerAndViewport.w;
  let pixel_size = tF * minT / (viewport_height * 0.5) * uni.perfParams.y;
  if (minT > 0.001 && minDist < pixel_size) {
    let p       = ro + rd * minT;
    let surfA   = clamp(1.0 - minDist / pixel_size, 0.0, 1.0);
    let clipPos = uni.vpMatrix * vec4f(p, 1.0);
    return FastFragOutput(vec4f(0.0, 0.0, 0.0, surfA), clipPos.z / clipPos.w);
  }
  discard;
  return FastFragOutput(vec4f(0.0), 1.0);
}`;export{e as default};