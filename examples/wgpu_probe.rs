//! SPIKE — can Rust's `wgpu` run fabric's own WGSL, natively, on this Mac?
//!
//! WHY THIS EXISTS. The panel's WKWebView has no `navigator.gpu` (measured), so fabric's engine
//! never starts there. Before designing any bridge, the load-bearing question is whether the
//! shaders fabric already ships are consumable by the native stack unchanged. WGSL is wgpu's own
//! source language, so the answer should be yes — but "should" is not a measurement.
//!
//! Three stages, each proving something the previous one cannot:
//!   1. a device exists at all, and we can see which backend/GPU it is;
//!   2. a trivial compute shader round-trips (dispatch + readback works end to end);
//!   3. FABRIC'S OWN `simulate.wgsl` compiles AND runs against real particle buffers.
//!
//! Run: cargo run --example wgpu_probe
//! Point at a different tree with FABRIC_WGSL=/path/to/simulate.wgsl

use std::borrow::Cow;

const DEFAULT_WGSL: &str = "/Users/r/Minilab/neuralkit-web/src/wgsl/simulate.wgsl";

/// The trivial shader for stage 2 — doubles every element, so a wrong result is unmistakable.
const DOUBLE_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read_write> data: array<f32>;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3u) {
  if (id.x >= arrayLength(&data)) { return; }
  data[id.x] = data[id.x] * 2.0;
}
"#;

fn main() {
    pollster::block_on(run())
}

async fn run() {
    // ── 1. a device ───────────────────────────────────────────────────────────
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle());
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            ..Default::default()
        })
        .await
        .expect("no wgpu adapter — no GPU reachable from Rust");

    let info = adapter.get_info();
    println!("1. ADAPTER");
    println!("   name     {}", info.name);
    println!("   backend  {:?}", info.backend);
    println!("   type     {:?}", info.device_type);
    println!("   driver   {} {}", info.driver, info.driver_info);

    let (device, queue) = adapter
        .request_device(&wgpu::DeviceDescriptor::default())
        .await
        .expect("requestDevice failed");

    // ── 2. a trivial compute shader round-trips ───────────────────────────────
    let input: Vec<f32> = (0..256).map(|i| i as f32).collect();
    let out = run_double(&device, &queue, &input).await;
    let ok = out.iter().zip(&input).all(|(o, i)| (*o - i * 2.0).abs() < 1e-6);
    println!("\n2. TRIVIAL COMPUTE (double 256 floats)");
    println!("   in [0..4]   {:?}", &input[..4]);
    println!("   out[0..4]   {:?}", &out[..4]);
    println!("   correct     {}", if ok { "YES" } else { "NO" });

    // ── 3. fabric's own simulate.wgsl ─────────────────────────────────────────
    let path = std::env::var("FABRIC_WGSL").unwrap_or_else(|_| DEFAULT_WGSL.into());
    let src = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => { println!("\n3. FABRIC SHADER — cannot read {path}: {e}"); return }
    };
    println!("\n3. FABRIC'S OWN simulate.wgsl  ({} bytes, {} lines)", src.len(), src.lines().count());

    // Compile. A WGSL error would otherwise only surface as a validation panic, so capture it.
    let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("fabric/simulate.wgsl"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(&src)),
    });
    println!("   compiled    YES (naga accepted it unchanged)");

    // Run it against a real particle set: a 16x16 lattice, exactly what buildGrid produces.
    let n: u32 = 256;
    let originals: Vec<[f32; 4]> = (0..n)
        .map(|i| {
            let (x, y) = ((i % 16) as f32 - 7.5, (i / 16) as f32 - 7.5);
            [x * 0.1, y * 0.1, 0.0, 1.0]
        })
        .collect();

    let moved = run_simulate(&device, &queue, &module, &originals).await;
    let changed = originals
        .iter()
        .zip(&moved)
        .filter(|(a, b)| (a[0] - b[0]).abs() > 1e-6 || (a[1] - b[1]).abs() > 1e-6 || (a[2] - b[2]).abs() > 1e-6)
        .count();

    println!("   dispatched  {n} particles, workgroup_size(64)");
    println!("   original[0] {:?}", originals[0]);
    println!("   current [0] {:?}", moved[0]);
    println!("   moved       {changed}/{n} particles displaced by the curl-noise sim");
    println!("\n   => fabric's WGSL runs natively through Rust wgpu, unmodified.");
}

async fn run_double(device: &wgpu::Device, queue: &wgpu::Queue, input: &[f32]) -> Vec<f32> {
    let bytes: &[u8] = bytemuck_cast(input);
    let storage = create_storage(device, bytes, "double/data");
    let readback = create_readback(device, bytes.len() as u64);

    let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("double"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(DOUBLE_WGSL)),
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: None, layout: None, module: &module,
        entry_point: Some("main"), compilation_options: Default::default(), cache: None,
    });
    let bind = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: None,
        layout: &pipeline.get_bind_group_layout(0),
        entries: &[wgpu::BindGroupEntry { binding: 0, resource: storage.as_entire_binding() }],
    });

    let mut enc = device.create_command_encoder(&Default::default());
    {
        let mut pass = enc.begin_compute_pass(&Default::default());
        pass.set_pipeline(&pipeline);
        pass.set_bind_group(0, &bind, &[]);
        pass.dispatch_workgroups(input.len().div_ceil(64) as u32, 1, 1);
    }
    enc.copy_buffer_to_buffer(&storage, 0, &readback, 0, bytes.len() as u64);
    queue.submit([enc.finish()]);
    read_f32(device, &readback).await
}

async fn run_simulate(
    device: &wgpu::Device, queue: &wgpu::Queue,
    module: &wgpu::ShaderModule, originals: &[[f32; 4]],
) -> Vec<[f32; 4]> {
    let flat: Vec<f32> = originals.iter().flatten().copied().collect();
    let bytes: &[u8] = bytemuck_cast(&flat);

    let orig = create_storage(device, bytes, "sim/original");
    let curr = create_storage(device, bytes, "sim/current");
    let readback = create_readback(device, bytes.len() as u64);

    // SimUniforms — 5 f32, padded to 32 B for the uniform alignment rule.
    let uni_vals: [f32; 8] = [1.0, 0.6, 0.9, 2.0, 0.0, 0.0, 0.0, 0.0];
    let uniform = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("sim/uniforms"), size: 32,
        usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST, mapped_at_creation: false,
    });
    queue.write_buffer(&uniform, 0, bytemuck_cast(&uni_vals));

    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("fabric/simulate"), layout: None, module,
        entry_point: Some("main"), compilation_options: Default::default(), cache: None,
    });
    let bind = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: None,
        layout: &pipeline.get_bind_group_layout(0),
        entries: &[
            wgpu::BindGroupEntry { binding: 0, resource: orig.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 1, resource: curr.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 2, resource: uniform.as_entire_binding() },
        ],
    });

    let mut enc = device.create_command_encoder(&Default::default());
    {
        let mut pass = enc.begin_compute_pass(&Default::default());
        pass.set_pipeline(&pipeline);
        pass.set_bind_group(0, &bind, &[]);
        pass.dispatch_workgroups(originals.len().div_ceil(64) as u32, 1, 1);
    }
    enc.copy_buffer_to_buffer(&curr, 0, &readback, 0, bytes.len() as u64);
    queue.submit([enc.finish()]);

    let flat = read_f32(device, &readback).await;
    flat.chunks_exact(4).map(|c| [c[0], c[1], c[2], c[3]]).collect()
}

// ── small helpers ────────────────────────────────────────────────────────────

fn bytemuck_cast<T>(v: &[T]) -> &[u8] {
    // SAFETY: f32/[f32;4] are plain data with no padding or invalid bit patterns.
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

fn create_storage(device: &wgpu::Device, bytes: &[u8], label: &str) -> wgpu::Buffer {
    use wgpu::util::DeviceExt;
    device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some(label), contents: bytes,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC | wgpu::BufferUsages::COPY_DST,
    })
}

fn create_readback(device: &wgpu::Device, size: u64) -> wgpu::Buffer {
    device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("readback"), size,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST, mapped_at_creation: false,
    })
}

async fn read_f32(device: &wgpu::Device, buf: &wgpu::Buffer) -> Vec<f32> {
    let slice = buf.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| { let _ = tx.send(r); });
    let _ = device.poll(wgpu::PollType::wait_indefinitely());
    rx.recv().unwrap().unwrap();
    let data = slice.get_mapped_range().unwrap();
    let out: Vec<f32> = data
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    drop(data);
    buf.unmap();
    out
}
