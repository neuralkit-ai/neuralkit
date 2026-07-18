use clap::Parser;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::time::{Duration, Instant};

mod signal_processing;
mod streaming;
mod tui;

use signal_processing::{BandData, SLIDING_WINDOW_STEP, WINDOW_SIZE};
use std::sync::atomic::Ordering;
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

/// Selectable MoQ protocols for the picker popup. "Auto" = offer all ALPNs and
/// let the relay choose (today's default); the rest force a single version on
/// the client (maps to `moq_net::Version`).
const PROTOCOLS: &[&str] = &[
    "Auto",
    "moq-lite-04",
    "moq-lite-03",
    "moq-transport-19",
    "moq-transport-18",
    "moq-transport-17",
    "moq-transport-16",
    "moq-transport-15",
    "moq-transport-14",
];

/// Top-level menu entries — each drills into a submenu.
const MAIN_MENU: &[&str] = &["Protocol", "Relay"];

/// Selectable relays (name, URL). Local carries the phaze-relay `--local`
/// address so the ip:port is visible in the picker.
const RELAYS: &[(&str, &str)] = &[
    ("Cloudflare", "https://relay.cloudflare.mediaoverquic.com"),
    ("Local", "https://127.0.0.1:4443"),
];

/// Drill-down settings menu state (opened with `M`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Menu {
    Closed,
    Main,
    Protocol,
    Relay,
}

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
        default_value = "https://relay.cloudflare.mediaoverquic.com"
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
    /// Displayed band heights, eased toward `last_band_data` each rendered frame
    /// so the bars glide smoothly between the synced 4 Hz FFT updates. Display
    /// only — the data/sync path never reads this.
    pub shown_bands: BandData,
    pub processing_counter: usize,
    pub use_custom_processing: bool,
    pub synthetic: bool,
    pub synthetic_time: f32,
    /// Last whole-second at which synthetic eSense (attention/meditation) updated,
    /// so it ticks at ~1 Hz like the real headset's big packet.
    pub last_esense_sec: u32,
    /// xorshift PRNG state for synthetic randomness (organic noise on the signal).
    pub rng: u32,
    /// Per-band amplitude multipliers [delta,theta,alpha,beta,gamma] that
    /// random-walk over time, so synthetic band powers drift erratically.
    pub band_amp: [f32; 5],
    /// Drill-down settings menu (`M`): Closed → Main → {Protocol, Relay}.
    pub menu: Menu,
    /// Highlighted row in the current menu level.
    pub menu_cursor: usize,
    /// Live-shared relay + protocol selection. The menu writes it and pings
    /// `reconfigure`; the connection task reads it and re-dials. Applied indices
    /// (0 = Auto / Cloudflare) live in here.
    pub sel: streaming::Selection,
    pub is_paused: bool,
    pub show_debug: bool,
    /// How many trailing raw samples the EEG wave widget plots — the horizontal
    /// zoom. Fewer = more zoomed-in (each cycle spreads wider). `-`/`+` adjust it,
    /// clamped to 64..=WINDOW_SIZE. Display only.
    pub raw_window: usize,
    pub stream_tx: Option<mpsc::Sender<NeuroPacket>>,
    pub moq_status: Arc<Mutex<String>>,
    pub moq_debug: Arc<Mutex<VecDeque<String>>>,
    pub moq_version: Arc<Mutex<String>>,
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
            shown_bands: BandData::default(),
            processing_counter: 0,
            use_custom_processing: true,
            synthetic: false,
            synthetic_time: 0.0,
            last_esense_sec: u32::MAX,
            rng: 0x2545F491,
            band_amp: [0.7; 5],
            menu: Menu::Closed,
            menu_cursor: 0,
            sel: streaming::Selection::new(0),
            is_paused: false,
            show_debug: false,
            raw_window: 256,
            stream_tx: None,
            moq_status: Arc::new(Mutex::new("Offline".to_string())),
            moq_debug: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            moq_version: Arc::new(Mutex::new(String::new())),
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

    /// Cheap xorshift PRNG → f32 in [-1.0, 1.0]. Adds organic randomness to the
    /// synthetic signal without pulling in a rand dependency.
    fn next_noise(&mut self) -> f32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        (x as f32 / u32::MAX as f32) * 2.0 - 1.0
    }

    pub fn generate_synthetic_data(&mut self) {
        self.last_poor_signal = 0;
        self.synthetic_time += 1.0 / 512.0;
        let t = self.synthetic_time;

        // Random-walk each band's amplitude so the relative band powers drift
        // erratically over time (erratic bands + oscilloscope), instead of the
        // old smooth deterministic modulation.
        for i in 0..5 {
            let step = self.next_noise() * 0.03;
            self.band_amp[i] = (self.band_amp[i] + step).clamp(0.1, 1.3);
        }

        let delta = (t * 2.0 * 2.0 * std::f32::consts::PI).sin() * 600.0 * self.band_amp[0];
        let theta = (t * 6.0 * 2.0 * std::f32::consts::PI).sin() * 300.0 * self.band_amp[1];
        let alpha = (t * 10.0 * 2.0 * std::f32::consts::PI).sin() * 450.0 * self.band_amp[2];
        let beta = (t * 22.0 * 2.0 * std::f32::consts::PI).sin() * 200.0 * self.band_amp[3];
        let gamma = (t * 40.0 * 2.0 * std::f32::consts::PI).sin() * 100.0 * self.band_amp[4];

        // Deterministic hum + a random component for organic, EEG-like texture.
        let rnd = self.next_noise() * 150.0;
        let noise = ((t * 1000.0).sin() * 40.0) + ((t * 2345.0).cos() * 20.0) + rnd;

        let raw = (delta + theta + alpha + beta + gamma + noise) as i16;

        self.raw_history.push_back(raw);
        if self.raw_history.len() > WINDOW_SIZE {
            self.raw_history.pop_front();
        }

        // Attention/Meditation — gated to ~1 Hz to mirror the real headset's
        // once-per-second big packet (previously updated at the 4 Hz FFT cadence,
        // faster than any real device). `has_*_update` then correctly marks the
        // 1 Hz event on the packet that carries it.
        let cur_sec = t as u32;
        if cur_sec != self.last_esense_sec {
            self.last_esense_sec = cur_sec;
            let last_att = self.attention_history.back().cloned().unwrap_or(50) as i32;
            let last_med = self.meditation_history.back().cloned().unwrap_or(50) as i32;
            let att = (last_att + (self.next_noise() * 15.0) as i32).clamp(20, 90) as u64;
            let med = (last_med + (self.next_noise() * 15.0) as i32).clamp(20, 90) as u64;
            self.attention_history.push_back(att);
            self.attention_update_pending = true;
            self.meditation_history.push_back(med);
            self.meditation_update_pending = true;
            if self.attention_history.len() > 100 {
                self.attention_history.pop_front();
            }
            if self.meditation_history.len() > 100 {
                self.meditation_history.pop_front();
            }
        }

        // Bands — FFT at the 4 Hz sliding-window cadence (unchanged).
        self.processing_counter += 1;
        if self.processing_counter >= SLIDING_WINDOW_STEP {
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

/// Handle one key press; returns true if the user asked to quit. One place for
/// both event-poll sites, and for the protocol popup so its navigation isn't
/// duplicated. When the popup is open it captures the keys.
fn handle_key(parser: &mut BrainWaveParser, code: KeyCode) -> bool {
    use Menu::*;
    if parser.menu != Closed {
        let len = match parser.menu {
            Main => MAIN_MENU.len(),
            Protocol => PROTOCOLS.len(),
            Relay => RELAYS.len(),
            Closed => 0,
        };
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                parser.menu_cursor = parser.menu_cursor.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                parser.menu_cursor = (parser.menu_cursor + 1).min(len.saturating_sub(1));
            }
            // Enter / → drills in (Main) or applies the item and closes (submenu).
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => match parser.menu {
                Main => match parser.menu_cursor {
                    0 => {
                        parser.menu = Protocol;
                        parser.menu_cursor = parser.sel.protocol.load(Ordering::Relaxed);
                    }
                    1 => {
                        parser.menu = Relay;
                        parser.menu_cursor = parser.sel.relay.load(Ordering::Relaxed);
                    }
                    _ => {}
                },
                Protocol => {
                    parser.sel.protocol.store(parser.menu_cursor, Ordering::Relaxed);
                    parser.sel.reconfigure.notify_one(); // re-dial with the new ALPN
                    parser.menu = Closed; // selection made — close the popup
                }
                Relay => {
                    parser.sel.relay.store(parser.menu_cursor, Ordering::Relaxed);
                    parser.sel.reconfigure.notify_one(); // re-dial the new relay
                    parser.menu = Closed; // selection made — close the popup
                }
                Closed => {}
            },
            // Esc / ← backs up a level (or closes from Main).
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => match parser.menu {
                Main => parser.menu = Closed,
                Protocol | Relay => {
                    parser.menu = Main;
                    parser.menu_cursor = 0;
                }
                Closed => {}
            },
            KeyCode::Char('m') | KeyCode::Char('q') => parser.menu = Closed,
            _ => {}
        }
        return false;
    }
    match code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('p') => parser.is_paused = !parser.is_paused,
        KeyCode::Char('d') => parser.show_debug = !parser.show_debug,
        KeyCode::Char('m') => {
            parser.menu = Menu::Main;
            parser.menu_cursor = 0;
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            parser.raw_window = parser.raw_window.saturating_sub(32).max(64);
        }
        KeyCode::Char('-') | KeyCode::Char('_') => {
            parser.raw_window = (parser.raw_window + 32).min(WINDOW_SIZE);
        }
        _ => {}
    }
    false
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

    // Live relay/protocol selection, shared by the dashboard (M-menu) and the
    // connection task. Seed the relay index from --stream-url so the picker
    // matches the dialed relay (Local when loopback, else Cloudflare).
    let initial_relay =
        if args.stream_url.contains("127.0.0.1") || args.stream_url.contains("localhost") {
            1
        } else {
            0
        };
    let sel = streaming::Selection::new(initial_relay);
    parser.sel = sel.clone();

    // 2. Setup Streaming (Publisher or Subscriber)
    let (tx, mut rx_packets) = mpsc::channel::<NeuroPacket>(100);

    if args.sub {
        let mut client =
            crate::streaming::SubscriberClient::new(&args.stream_url, &args.stream_path)?;
        client.status = parser.moq_status.clone();
        client.debug = parser.moq_debug.clone();
        client.version = parser.moq_version.clone();
        client.net_latency_ms = parser.net_latency_ms.clone();
        client.sel = sel.clone();
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
        client.version = parser.moq_version.clone();
        client.net_latency_ms = parser.net_latency_ms.clone();
        client.sel = sel.clone();
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
                        Event::Key(key) => {
                            if handle_key(&mut parser, key.code) {
                                break;
                            }
                        }
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

            // Ease the displayed band heights toward the real (synced 4 Hz) values
            // every frame (~30 fps) so the bars glide instead of stepping. Display
            // only — the raw wave, the FFT data, and the pub/sub sync are untouched.
            // Frozen on pause so P freezes the bars exactly.
            if !parser.is_paused {
                if let Some(t) = parser.last_band_data.clone() {
                    const S: f32 = 0.3;
                    let s = &mut parser.shown_bands;
                    s.delta += (t.delta - s.delta) * S;
                    s.theta += (t.theta - s.theta) * S;
                    s.alpha += (t.alpha - s.alpha) * S;
                    s.beta += (t.beta - s.beta) * S;
                    s.gamma += (t.gamma - s.gamma) * S;
                }
            }

            terminal.draw(|f| tui::render_dashboard(f, &parser))?;
            last_tick = Instant::now();
        }

        if event::poll(Duration::from_millis(1))? {
            match event::read()? {
                Event::Key(key) => {
                    if handle_key(&mut parser, key.code) {
                        break;
                    }
                }
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
