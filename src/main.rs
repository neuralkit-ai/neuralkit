use clap::Parser;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::time::{Duration, Instant};

mod signal_processing;
mod streaming;
mod tui;

use signal_processing::{BandData, SLIDING_WINDOW_STEP, WINDOW_SIZE};
use std::sync::{Arc, Mutex};
use streaming::{NeuroPacket, StreamingClient};

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use tokio::sync::mpsc;

// Byte codes
const SYNC: u8 = 0xAA;
const EXCODE: u8 = 0x55;
const POOR_SIGNAL: u8 = 0x02;
const ATTENTION: u8 = 0x04;
const MEDITATION: u8 = 0x05;
const RAW_VALUE: u8 = 0x80;
const ASIC_EEG_POWER: u8 = 0x83;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Serial port to connect to
    #[arg(default_value = "/dev/cu.usbmodem8D762F6448571")]
    port: String,

    /// Run in synthetic data mode
    #[arg(short, long)]
    synthetic: bool,

    /// MoQ Relay URL (e.g. moqt://relay.quic.video)
    #[arg(
        short = 'u',
        long,
        default_value = "https://interop-relay.cloudflare.mediaoverquic.com"
    )]
    stream_url: String,

    /// MoQ Broadcast Path (e.g. neuralkit)
    #[arg(long, default_value = "neuralkit")]
    stream_path: String,

    /// Run as a subscriber to view the stream
    #[arg(long)]
    sub: bool,
}

pub struct BrainWaveParser {
    pub raw_data: Vec<i16>,
    pub noise_data: Vec<u8>,
    pub attention_data: Vec<u8>,
    pub meditation_data: Vec<u8>,
    pub band_list: Vec<BandData>,
    pub attention_history: VecDeque<u64>,
    pub meditation_history: VecDeque<u64>,
    pub raw_history: VecDeque<i16>,
    pub raw_buffer: VecDeque<i16>,
    pub bands_history: VecDeque<BandData>,
    pub last_poor_signal: u8,
    pub last_band_data: Option<BandData>,
    pub processing_counter: usize,
    pub use_custom_processing: bool,
    pub synthetic: bool,
    pub synthetic_time: f32,
    pub is_paused: bool,
    pub show_debug: bool,
    pub stream_tx: Option<mpsc::Sender<NeuroPacket>>,
    pub moq_status: Arc<Mutex<String>>,
    pub moq_debug: Arc<Mutex<VecDeque<String>>>,
    pub last_latency_ms: u64,
    pub net_latency_ms: Arc<std::sync::atomic::AtomicU64>,
    pub latest_attention: u64,
    pub latest_meditation: u64,
    pub attention_update_pending: bool,
    pub meditation_update_pending: bool,
    pub attention_queue: VecDeque<u64>,
    pub meditation_queue: VecDeque<u64>,
    pub sub_sample_count: usize,
}

impl BrainWaveParser {
    fn new() -> Self {
        Self {
            raw_data: Vec::new(),
            noise_data: Vec::new(),
            attention_data: Vec::new(),
            meditation_data: Vec::new(),
            band_list: Vec::new(),
            attention_history: VecDeque::new(),
            meditation_history: VecDeque::new(),
            raw_history: VecDeque::new(),
            raw_buffer: VecDeque::new(),
            bands_history: VecDeque::new(),
            last_poor_signal: 200,
            last_band_data: None,
            processing_counter: 0,
            use_custom_processing: true,
            synthetic: false,
            synthetic_time: 0.0,
            is_paused: false,
            show_debug: false,
            stream_tx: None,
            moq_status: Arc::new(Mutex::new("Offline".to_string())),
            moq_debug: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            last_latency_ms: 0,
            net_latency_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            latest_attention: 0,
            latest_meditation: 0,
            attention_update_pending: false,
            meditation_update_pending: false,
            attention_queue: VecDeque::new(),
            meditation_queue: VecDeque::new(),
            sub_sample_count: 0,
        }
    }

    fn push_packet(&mut self, bands: &BandData) {
        if let Some(tx) = &self.stream_tx {
            let packet = NeuroPacket {
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                delta: bands.delta,
                theta: bands.theta,
                alpha: bands.alpha,
                beta: bands.beta,
                gamma: bands.gamma,
                attention: self.attention_history.back().cloned().unwrap_or(0),
                meditation: self.meditation_history.back().cloned().unwrap_or(0),
                poor_signal: self.last_poor_signal as u32,
                raw_data: self.raw_history.iter().map(|&x| x as i32).collect(),
                has_attention_update: self.attention_update_pending,
                has_meditation_update: self.meditation_update_pending,
            };
            self.attention_update_pending = false;
            self.meditation_update_pending = false;
            let _ = tx.try_send(packet);
        }
    }

    fn parse_packet(&mut self, payload: &[u8]) {
        let mut i = 0;
        while i < payload.len() {
            let mut excode_level = 0;
            while i < payload.len() && payload[i] == EXCODE {
                excode_level += 1;
                i += 1;
            }

            if i >= payload.len() {
                break;
            }

            let code = payload[i];
            i += 1;

            if excode_level == 0 {
                match code {
                    POOR_SIGNAL => {
                        if i < payload.len() {
                            let val = payload[i];
                            i += 1;
                            self.last_poor_signal = val;
                        }
                    }
                    ATTENTION => {
                        if i < payload.len() {
                            let val = payload[i];
                            i += 1;
                            if val <= 100 {
                                self.attention_history.push_back(val as u64);
                                self.attention_update_pending = true;
                                if self.attention_history.len() > 100 {
                                    self.attention_history.pop_front();
                                }
                            }
                        }
                    }
                    MEDITATION => {
                        if i < payload.len() {
                            let val = payload[i];
                            i += 1;
                            if val <= 100 {
                                self.meditation_history.push_back(val as u64);
                                self.meditation_update_pending = true;
                                if self.meditation_history.len() > 100 {
                                    self.meditation_history.pop_front();
                                }
                            }
                        }
                    }
                    RAW_VALUE => {
                        if i < payload.len() {
                            let vlen = payload[i] as usize;
                            i += 1;
                            if i + vlen <= payload.len() && vlen == 2 {
                                let high = payload[i] as u16;
                                let low = payload[i + 1] as u16;
                                i += 2;
                                let raw = ((high << 8) | low) as i16;

                                self.raw_history.push_back(raw);
                                if self.raw_history.len() > WINDOW_SIZE {
                                    self.raw_history.pop_front();
                                }

                                self.processing_counter += 1;
                                if self.use_custom_processing
                                    && self.processing_counter >= SLIDING_WINDOW_STEP
                                {
                                    if self.raw_history.len() >= WINDOW_SIZE {
                                        let raw_slice: Vec<i16> =
                                            self.raw_history.iter().cloned().collect();
                                        if let Some(custom_bands) =
                                            signal_processing::process_brain_waves(&raw_slice)
                                        {
                                            self.push_packet(&custom_bands);
                                            self.last_band_data = Some(custom_bands.clone());
                                            self.bands_history.push_back(custom_bands);
                                            if self.bands_history.len() > 100 {
                                                self.bands_history.pop_front();
                                            }
                                        }
                                    }
                                    self.processing_counter = 0;
                                }
                            } else {
                                i += vlen;
                            }
                        }
                    }
                    ASIC_EEG_POWER => {
                        if i < payload.len() {
                            let vlen = payload[i] as usize;
                            i += 1;
                            if i + vlen <= payload.len() && vlen == 24 {
                                let mut values = Vec::new();
                                for _ in 0..8 {
                                    let b1 = payload[i] as u32;
                                    let b2 = payload[i + 1] as u32;
                                    let b3 = payload[i + 2] as u32;
                                    i += 3;
                                    let val = (b1 << 16) | (b2 << 8) | b3;
                                    values.push(val as f32);
                                }
                                let sum: f32 = values.iter().sum();
                                if sum > 0.0 {
                                    let bands = BandData {
                                        delta: values[0] / sum,
                                        theta: values[1] / sum,
                                        alpha: (values[2] + values[3]) / sum,
                                        beta: (values[4] + values[5]) / sum,
                                        gamma: (values[6] + values[7]) / sum,
                                    };
                                    if !self.use_custom_processing {
                                        self.push_packet(&bands);
                                        self.last_band_data = Some(bands.clone());
                                        self.bands_history.push_back(bands);
                                        if self.bands_history.len() > 100 {
                                            self.bands_history.pop_front();
                                        }
                                    }
                                }
                            } else {
                                i += vlen;
                            }
                        }
                    }
                    _ => {
                        if code >= 0x80 {
                            if i < payload.len() {
                                let vlen = payload[i] as usize;
                                i += 1 + vlen;
                            }
                        } else {
                            i += 1;
                        }
                    }
                }
            } else {
                if code >= 0x80 {
                    if i < payload.len() {
                        let vlen = payload[i] as usize;
                        i += 1 + vlen;
                    }
                } else {
                    i += 1;
                }
            }
        }
    }

    pub fn generate_synthetic_data(&mut self) {
        self.last_poor_signal = 0;
        self.synthetic_time += 1.0 / 512.0;
        let t = self.synthetic_time;

        let delta_mod = (t * 0.1).sin() * 0.3 + 0.7;
        let theta_mod = (t * 0.2).cos() * 0.4 + 0.6;
        let alpha_mod = (t * 0.5).sin() * 0.2 + 0.8;
        let beta_mod = (t * 0.7).cos() * 0.3 + 0.7;
        let gamma_mod = (t * 1.1).sin() * 0.5 + 0.5;

        let delta = (t * 2.0 * 2.0 * std::f32::consts::PI).sin() * 600.0 * delta_mod;
        let theta = (t * 6.0 * 2.0 * std::f32::consts::PI).sin() * 300.0 * theta_mod;
        let alpha = (t * 10.0 * 2.0 * std::f32::consts::PI).sin() * 450.0 * alpha_mod;
        let beta = (t * 22.0 * 2.0 * std::f32::consts::PI).sin() * 200.0 * beta_mod;
        let gamma = (t * 40.0 * 2.0 * std::f32::consts::PI).sin() * 100.0 * gamma_mod;

        let noise = (((t * 1000.0).sin() * 40.0) + ((t * 2345.0).cos() * 20.0)) as f32;

        let raw = (delta + theta + alpha + beta + gamma + noise) as i16;

        self.raw_history.push_back(raw);
        if self.raw_history.len() > WINDOW_SIZE {
            self.raw_history.pop_front();
        }

        self.processing_counter += 1;

        if self.processing_counter >= SLIDING_WINDOW_STEP {
            let mut last_att = self.attention_history.back().cloned().unwrap_or(50) as i32;
            let mut last_med = self.meditation_history.back().cloned().unwrap_or(50) as i32;

            let drift_att = (t * 0.3).sin() * 2.0;
            let drift_med = (t * 0.2).cos() * 2.0;

            last_att = (last_att + drift_att as i32).clamp(20, 90);
            last_med = (last_med + drift_med as i32).clamp(20, 90);

            self.attention_history.push_back(last_att as u64);
            self.attention_update_pending = true;
            self.meditation_history.push_back(last_med as u64);
            self.meditation_update_pending = true;

            if self.attention_history.len() > 100 {
                self.attention_history.pop_front();
            }
            if self.meditation_history.len() > 100 {
                self.meditation_history.pop_front();
            }

            if self.raw_history.len() >= WINDOW_SIZE {
                let raw_slice: Vec<i16> = self.raw_history.iter().cloned().collect();
                if let Some(custom_bands) = signal_processing::process_brain_waves(&raw_slice) {
                    self.push_packet(&custom_bands);
                    self.last_band_data = Some(custom_bands.clone());
                    self.bands_history.push_back(custom_bands);
                    if self.bands_history.len() > 100 {
                        self.bands_history.pop_front();
                    }
                }
            }
            self.processing_counter = 0;
        }
    }

    pub fn apply_packet(&mut self, packet: NeuroPacket) {
        if packet.has_attention_update {
            self.attention_queue.push_back(packet.attention);
        }
        if packet.has_meditation_update {
            self.meditation_queue.push_back(packet.meditation);
        }
        self.latest_attention = packet.attention;
        self.latest_meditation = packet.meditation;

        let bands = BandData {
            delta: packet.delta,
            theta: packet.theta,
            alpha: packet.alpha,
            beta: packet.beta,
            gamma: packet.gamma,
        };

        if self.bands_history.len() >= 100 {
            self.bands_history.pop_front();
        }
        self.bands_history.push_back(bands.clone());
        self.last_band_data = Some(bands);
        self.last_poor_signal = packet.poor_signal as u8;

        // Calculate network latency
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        self.last_latency_ms = now_ms.saturating_sub(packet.timestamp_ms);

        if !packet.raw_data.is_empty() {
            let new_points = packet.raw_data.iter().skip(packet.raw_data.len().saturating_sub(signal_processing::SLIDING_WINDOW_STEP)).map(|&x| x as i16);
            for p in new_points {
                self.raw_buffer.push_back(p);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Redirect tracing logs to a sink to prevent TUI corruption from background libraries
    // TUI owns the terminal — tracing goes to the debug log file instead of stdout.
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open("neuralkit_debug.log").expect("open neuralkit_debug.log");
    tracing_subscriber::fmt().with_writer(log_file).with_ansi(false).init();

    let args = Args::parse();

    let mut parser = BrainWaveParser::new();
    parser.synthetic = args.synthetic;

    // 2. Setup Streaming (Publisher or Subscriber)
    let (tx, mut rx_packets) = mpsc::channel::<NeuroPacket>(100);

    if args.sub {
        let mut client =
            crate::streaming::SubscriberClient::new(&args.stream_url, &args.stream_path)?;
        client.status = parser.moq_status.clone();
        client.debug = parser.moq_debug.clone();
        client.net_latency_ms = parser.net_latency_ms.clone();
        tokio::spawn(async move {
            if let Err(e) = client.run(tx).await {
                tracing::error!("Subscriber error: {:?}", e);
            }
        });
    } else {
        parser.stream_tx = Some(tx);
        let mut client = StreamingClient::new(&args.stream_url, &args.stream_path)?;
        client.status = parser.moq_status.clone();
        client.debug = parser.moq_debug.clone();
        let (tx_moq, rx_moq) = mpsc::channel(100);
        parser.stream_tx = Some(tx_moq);
        tokio::spawn(async move {
            if let Err(e) = client.run(rx_moq).await {
                tracing::error!("Publisher error: {:?}", e);
            }
        });
    }

    // 3. Serial Port Setup (only for Publisher, non-synthetic)
    let mut port = if !args.sub && !parser.synthetic {
        let port_name = args.port.clone();
        Some(
            serialport::new(&port_name, 57600)
                .timeout(Duration::from_millis(100))
                .open()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        )
    } else {
        None
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut buffer = [0u8; 1024];
    let mut stream_buffer = Vec::new();
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(33);

    // --synthetic pacing: emit raw samples at the real device rate (SAMPLE_RATE,
    // 512 Hz) by catching up to the wall clock, so synthetic behaves like the
    // hardware serial stream regardless of TUI render speed. (The old fixed
    // 16-samples-per-loop burst had no explicit rate — it ran ~9x real-time.)
    let synth_start = Instant::now();
    let mut synth_samples: u64 = 0;

    loop {
        if !parser.is_paused {
            if parser.synthetic {
                // Generate up to the sample count that SHOULD exist by now at
                // SAMPLE_RATE — self-correcting to the wall clock (real-hardware
                // timing), independent of how long a render/loop iteration takes.
                let target = (synth_start.elapsed().as_secs_f64()
                    * signal_processing::SAMPLE_RATE as f64) as u64;
                while synth_samples < target {
                    parser.generate_synthetic_data();
                    synth_samples += 1;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            } else if args.sub {
                // In subscriber mode: wait for packet, input, or tick timeout
                tokio::select! {
                    Some(packet) = rx_packets.recv() => {
                        parser.apply_packet(packet);
                        while let Ok(packet) = rx_packets.try_recv() {
                            parser.apply_packet(packet);
                        }
                    }
                    _ = tokio::time::sleep(tick_rate) => {}
                }
                
                // CRITICAL: We must pump the TUI event queue immediately after select.
                // If we don't, crossterm events pile up and block the OS thread or freeze the UI.
                if event::poll(Duration::from_millis(0))? {
                    match event::read()? {
                        Event::Key(key) => match key.code {
                            KeyCode::Char('q') => break,
                            KeyCode::Char('p') => parser.is_paused = !parser.is_paused,
                            KeyCode::Char('d') => parser.show_debug = !parser.show_debug,
                            _ => {}
                        },
                        Event::Resize(_, _) => {
                            terminal.autoresize()?;
                        }
                        _ => {}
                    }
                }
            } else if let Some(ref mut p) = port {
                // Serial reading is sync, but we use a short timeout.
                // In a true async app we'd use tokio-serial.
                match p.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        stream_buffer.extend_from_slice(&buffer[..n]);
                        while stream_buffer.len() >= 4 {
                            if stream_buffer[0] == SYNC && stream_buffer[1] == SYNC {
                                let p_length = stream_buffer[2] as usize;
                                if p_length > 169 {
                                    stream_buffer.remove(0);
                                    continue;
                                }
                                if stream_buffer.len() >= 3 + p_length + 1 {
                                    let payload = &stream_buffer[3..3 + p_length];
                                    let checksum = stream_buffer[3 + p_length];
                                    let mut sum: u32 = 0;
                                    for &b in payload {
                                        sum += b as u32;
                                    }
                                    let computed_checksum = (!(sum & 0xFF) & 0xFF) as u8;
                                    if computed_checksum == checksum {
                                        parser.parse_packet(payload);
                                    }
                                    stream_buffer.drain(0..3 + p_length + 1);
                                } else {
                                    break;
                                }
                            } else {
                                stream_buffer.remove(0);
                            }
                        }
                    }
                    Ok(_) => (),
                    Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => (),
                    Err(e) => {
                        disable_raw_mode()?;
                        let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
                        return Err(e.into());
                    }
                }
            }
        } else {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if last_tick.elapsed() >= tick_rate {
            // Gate the smoothing-drain on !is_paused (the receive stage already is),
            // so P freezes the raw wave + attention/meditation immediately — same as
            // the bands. The smoothing itself is untouched: it only stops WHILE
            // paused. terminal.draw stays outside, so the frozen frame still renders
            // and the TUI stays responsive.
            if args.sub && !parser.is_paused {
                let samples_to_pop = (signal_processing::SAMPLE_RATE as f32 * last_tick.elapsed().as_secs_f32()) as usize;
                let mut popped = 0;
                while popped < samples_to_pop && !parser.raw_buffer.is_empty() {
                    if let Some(val) = parser.raw_buffer.pop_front() {
                        parser.raw_history.push_back(val);
                        if parser.raw_history.len() > signal_processing::WINDOW_SIZE {
                            parser.raw_history.pop_front();
                        }
                        
                        // Push attention/meditation ONLY when the publisher signaled an actual hardware update event occurred.
                        // We pop these from the queue so they appear at exactly the same "wave offset" as they did on the publisher.
                        if let Some(att) = parser.attention_queue.pop_front() {
                            parser.attention_history.push_back(att);
                            if parser.attention_history.len() > 100 {
                                parser.attention_history.pop_front();
                            }
                        }
                        if let Some(med) = parser.meditation_queue.pop_front() {
                            parser.meditation_history.push_back(med);
                            if parser.meditation_history.len() > 100 {
                                parser.meditation_history.pop_front();
                            }
                        }
                    }
                    popped += 1;
                }
                
                // Anti-pileup measure if network lags and then dumps huge batch of packets at once
                if parser.raw_buffer.len() > 1024 {
                    parser.raw_buffer.drain(0..(parser.raw_buffer.len() - signal_processing::WINDOW_SIZE));
                }
            }

            terminal.draw(|f| tui::render_dashboard(f, &parser))?;
            last_tick = Instant::now();
        }

        if event::poll(Duration::from_millis(1))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('p') => parser.is_paused = !parser.is_paused,
                    KeyCode::Char('d') => parser.show_debug = !parser.show_debug,
                    _ => {}
                },
                Event::Resize(_, _) => {
                    terminal.autoresize()?;
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
