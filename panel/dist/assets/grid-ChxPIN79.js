var e=`struct Object {
  pos_rounding: vec4f,
  size_type:    vec4f,
  rotation:     vec3f,
  hColor:       u32,
  material:     vec4u,
  glow_color:   u32,
  glow_intensity: f32,
  glow_radius:    f32,
  glow_reserved:  f32,
  
  
  
  modifier:       vec4f,
  modifier2:      vec4f,
  modifier3:      vec4f
}

struct Cell {
  count: atomic<u32>,
  indices: array<u32, 15>, 
}

struct Grid {
  cells: array<Cell, 32768>, 
}

struct SimUniforms {
  time:          f32,
  curlFreq:      f32,
  curlAmplitude: f32,
  maxDistance:   f32,
  numObjects:    f32
}

@group(0) @binding(0) var<storage, read_write> grid: Grid;
@group(0) @binding(1) var<storage, read> objects: array<Object>;
@group(0) @binding(2) var<uniform> sim: SimUniforms;

const GRID_RES: u32 = 32u;
const GRID_SIZE: f32 = 32.0;

@compute @workgroup_size(64)
fn clear_grid(@builtin(global_invocation_id) id: vec3u) {
  let idx = id.x;
  if (idx >= 32768u) { return; }
  atomicStore(&grid.cells[idx].count, 0u);
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

@compute @workgroup_size(64)
fn assign_objects(@builtin(global_invocation_id) id: vec3u) {
  let iid = id.x;
  if (iid >= u32(sim.numObjects)) { return; }

  let o = objects[iid];
  let typeId = o.size_type.w;
  let pos = o.pos_rounding.xyz;
  let rot = o.rotation.xyz;
  let sz  = o.size_type.xyz;
  
  
  var minP = vec3f(1e4);
  var maxP = vec3f(-1e4);

  
  var env = sz;
  if (typeId < 0.5) { 
     env = sz + o.pos_rounding.w;
  } else if (typeId < 1.5) { 
     env = vec3f(sz.x, sz.y + sz.x, sz.x);
  } else if (typeId < 2.5) { 
     env = sz.xxx;
  } else if (typeId < 3.5) { 
     env = vec3f(sz.x + sz.y, sz.y, sz.x + sz.y);
  } else if (typeId < 4.5) { 
     env = sz;
  } else if (typeId < 5.5) { 
     env = vec3f(sz.x, sz.y, sz.x);
  } else if (typeId < 6.5) { 
     env = vec3f(sz.x, sz.y, sz.x);
  } else if (typeId < 7.5) { 
     env = vec3f(sz.x, sz.y, sz.x);
  } else if (typeId < 8.5) { 
     let rmax = max(sz.x, sz.z);
     env = vec3f(rmax, sz.y, rmax);
  } else if (typeId < 9.5) { 
     env = vec3f(sz.x, sz.y, sz.x);
  } else if (typeId < 10.5) { 
     env = sz.xxx;
  } else if (typeId < 11.5) { 
     env = vec3f(sz.x, sz.y, sz.x);
  } else if (typeId < 12.5) { 
     env = sz;
  } else if (typeId < 13.5) { 
     env = vec3f(sz.x, sz.y, sz.x);
  } else if (typeId < 14.5) { 
     let rmax = max(sz.x, sz.z);
     env = vec3f(rmax, sz.y + rmax, rmax);
  } else if (typeId < 15.5) { 
     env = sz + o.pos_rounding.w;
  } else if (typeId < 16.5) { 
     env = vec3f(sz.x + o.pos_rounding.w, sz.z, sz.y + o.pos_rounding.w);
  } else if (typeId < 17.5) { 
     env = sz.xxx;
  } else if (typeId < 18.5) { 
     let r = sz.x + sz.z;
     env = vec3f(r, r, r);
  } else if (typeId < 19.5) { 
     env = sz.xxx;
  } else if (typeId < 20.5) { 
     env = vec3f(sz.y, sz.y, sz.y);
  } else if (typeId < 21.5) { 
     env = vec3f(sz.x + sz.z, sz.y + sz.x + sz.z, sz.z);
  } else if (typeId > 29.5 && typeId < 32.5) {
     
     
     var ext2: vec2f;
     if (typeId < 30.5) {
       ext2 = vec2f(sz.x, sz.x);              
     } else {
       ext2 = sz.xy + o.pos_rounding.w;       
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

  
  let corners = array<vec3f, 8>(
    vec3f(-1,-1,-1), vec3f(1,-1,-1), vec3f(-1,1,-1), vec3f(1,1,-1),
    vec3f(-1,-1,1),  vec3f(1,-1,1),  vec3f(-1,1,1),  vec3f(1,1,1)
  );

  for (var c = 0; c < 8; c++) {
    let pLocal = corners[c] * env;
    let pWorld = rotateXYZ(pLocal, rot) + pos;
    minP = min(minP, pWorld);
    maxP = max(maxP, pWorld);
  }

  
  
  let xStart = i32(clamp(floor((minP.x + 32.0) * 0.5), 0.0, 31.0));
  let xEnd   = i32(clamp(floor((maxP.x + 32.0) * 0.5), 0.0, 31.0));
  let yStart = i32(clamp(floor((minP.y + 32.0) * 0.5), 0.0, 31.0));
  let yEnd   = i32(clamp(floor((maxP.y + 32.0) * 0.5), 0.0, 31.0));
  let zStart = i32(clamp(floor((minP.z + 96.0) * 0.25), 0.0, 31.0));
  let zEnd   = i32(clamp(floor((maxP.z + 96.0) * 0.25), 0.0, 31.0));

  
  for (var x = xStart; x <= xEnd; x++) {
    for (var y = yStart; y <= yEnd; y++) {
      for (var z = zStart; z <= zEnd; z++) {
        let cellIdx = u32(x) + u32(y) * GRID_RES + u32(z) * GRID_RES * GRID_RES;
        
        
        let slot = atomicAdd(&grid.cells[cellIdx].count, 1u);
        if (slot < 15u) {
          grid.cells[cellIdx].indices[slot] = iid;
        }
      }
    }
  }
}`;export{e as default};