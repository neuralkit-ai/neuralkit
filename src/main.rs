use clap::Parser;
use std::collections::VecDeque;
use std::io::{self, IsTerminal, Read};
use std::time::{Duration, Instant};

mod login;
mod passkey;
mod totp;
mod session;
mod style;
mod signal_processing;
mod streaming;
#[cfg(target_os = "macos")]
mod tray;
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

/// Top-level menu entries — each drills into a submenu.
const MAIN_MENU: &[&str] = &["Relay", "Transport"];

/// Selectable relays (name, URL). Local carries the phaze-relay `--local`
/// address so the ip:port is visible in the picker. Cloudflare points at
/// PRODUCTION — phaze-moq's direct subscribe-by-name is exactly the
/// mechanism prod requires, so this just works, unlike the old moq-net-based
/// client which needed announce forwarding prod never provides. Interop is
/// Cloudflare's other public relay (the former "Cloudflare" entry, before
/// prod was verified reachable) — same moqt-16 wire, expired TLS cert
/// (`is_insecure` already matches any mediaoverquic.com host).
const RELAYS: &[(&str, &str)] = &[
    ("Cloudflare", "https://relay.cloudflare.mediaoverquic.com"),
    ("Local", "https://127.0.0.1:4443"),
    (
        "Interop",
        "https://interop-relay.cloudflare.mediaoverquic.com",
    ),
];

/// Selectable wire transports. Both negotiate the identical moqt-16 codec —
/// WebTransport wraps it over HTTP/3, RawQuic sends it directly over QUIC.
/// Not a version list: moq-transport only ever speaks draft-16, so this is
/// the one real choice moq-native-ietf's client has (see phaze-moq's `dial`).
const TRANSPORTS: &[(&str, phaze_moq::Transport)] = &[
    ("WebTransport", phaze_moq::Transport::WebTransport),
    ("Raw QUIC", phaze_moq::Transport::RawQuic),
];

/// Drill-down settings menu state (opened with `M`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Menu {
    Closed,
    Main,
    Relay,
    Transport,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// `neuralkit auth login` — sign in with your passkey; anything else runs the TUI.
    #[command(subcommand)]
    command: Option<Command>,

    /// Serial port to connect to
    #[arg(default_value = "/dev/cu.usbmodem8D762F6448571")]
    port: String,

    /// Run in synthetic data mode
    #[arg(short, long)]
    synthetic: bool,

    /// MoQ Relay URL (defaults to the local phaze-relay; pass a public relay
    /// like https://relay.cloudflare.mediaoverquic.com to go remote)
    #[arg(short = 'u', long, default_value = "https://127.0.0.1:4443")]
    stream_url: String,

    /// MoQ Broadcast Path (e.g. neuralkit)
    #[arg(long, default_value = "neuralkit")]
    stream_path: String,

    /// Run as a subscriber to view the stream
    #[arg(long)]
    sub: bool,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Authentication — sign in and manage credentials.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// A menu-bar icon for this machine — status at a glance. Runs until quit.
    ///
    /// v0 is read-only: who is signed in, which tier of key this machine holds, and the
    /// site a click away. It starts no ceremonies — those arrive with the desktop app.
    Tray {
        /// The site the "Open" item points at.
        #[arg(long, default_value = "https://neuralkit.ai")]
        url: String,
    },
}

/// The two halves of a native passkey. Separate verbs because they are separate acts: one
/// needs an existing session and changes server state, the other needs neither.
#[derive(clap::Subcommand, Debug)]
enum PasskeyAction {
    /// Bind this machine's key to the account you are signed in as. Needs a session.
    Register {
        #[arg(long, default_value = "https://neuralkit.ai")]
        url: String,
    },
    /// Sign in using this machine's key — no browser, no phone, no code.
    Login {
        #[arg(long, default_value = "https://neuralkit.ai")]
        url: String,
    },
    /// Ask macOS for the ACCOUNT's own passkey — the bootstrap path that needs no email.
    ///
    /// Uses the credential already on your Apple ID (the one your phone registered, synced
    /// through iCloud Keychain) rather than a key this machine holds. Needs the signed build,
    /// an associated domain, and a GUI session — it cannot work over SSH.
    System {
        #[arg(long, default_value = "https://neuralkit.ai")]
        url: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum TotpAction {
    /// Set up an authenticator app against the account you are signed in as.
    Setup {
        #[arg(long, default_value = "https://neuralkit.ai")]
        url: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum AuthCommand {
    /// Sign in — and register this machine, so later sign-ins have more ways in.
    ///
    /// Every path registers as it goes: the QR scan stages the install's key, and a successful
    /// sign-in mints a passkey. So a machine that has signed in once can later use an
    /// authenticator code or its own passkey, and is offered whichever actually work.
    Login {
        /// The Neuralkit app origin (serves the QR.request stream + /passkey page).
        #[arg(long, default_value = "https://neuralkit.ai")]
        url: String,
        /// Sign in by scanning a QR code with your phone. Works on any machine.
        #[arg(long, conflicts_with_all = ["totp", "passkey", "email"])]
        qr: bool,
        /// Sign in with your authenticator app. Needs a previous sign-in on this machine —
        /// that is what leaves the account id on disk.
        #[arg(long, conflicts_with_all = ["passkey", "email"])]
        totp: bool,
        /// Sign in with this machine's own passkey. Needs a previous sign-in on this machine —
        /// any path registers one, so this appears from the second sign-in onward.
        #[arg(long)]
        passkey: bool,
        /// Sign in with a code emailed to you. The only path that needs nothing on this
        /// machine, so it is how a machine that has never signed in gets started.
        #[arg(long)]
        email: bool,
    },
    /// This machine's own passkey — create it if absent, and prove it can assert.
    ///
    /// Held natively: no browser, no WebAuthn API. Deliberately outlives sessions, so
    /// `logout` and expiry leave it alone and only `unregister` removes it.
    Passkey {
        /// `register` binds this machine's key to the signed-in account; `login` signs in with
        /// it. With neither, the command just shows the credential and self-tests it offline.
        #[command(subcommand)]
        action: Option<PasskeyAction>,
        /// The origin the assertion is bound to — WebAuthn signs the host, so this decides
        /// which server would accept it.
        #[arg(long, default_value = "https://neuralkit.ai")]
        url: String,
    },
    /// Authenticator app — the one path that cannot register itself.
    ///
    /// Setup needs a human to scan a code and type six digits back, so unlike the passkey
    /// it is a command rather than something a sign-in does quietly. The browser page enrols
    /// the same way; either surface produces the same secret.
    #[command(subcommand)]
    Totp(TotpAction),
    /// Forget this machine — revoke its session and clear its registration.
    ///
    /// Deliberately not called logout: logging out ends a session and leaves the machine
    /// registered, which is what lets the next sign-in be a code. This removes the
    /// registration itself, so the next `auth login` starts from a QR as a machine that
    /// had never signed in would.
    ///
    /// Takes no `--url`: the origin comes from the machine's own credentials, since it
    /// recorded where it registered. A repeated (or defaulted) origin here could revoke
    /// nothing while the delete still succeeded, leaving a live session with nothing on
    /// disk to reach it.
    Unregister,
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
    /// Set once at startup from `--sub`. Gates the `R` reconnect key — force-
    /// redialing is a subscriber concept (the publisher's outer loop already
    /// redials on its own the moment a write fails).
    pub is_subscriber: bool,
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
    /// zoom. Fewer = more zoomed-in (each cycle spreads wider). `-`/`+` step it by
    /// one sliding window (SLIDING_WINDOW_STEP = 128 = 250 ms), clamped to
    /// SLIDING_WINDOW_STEP..=WINDOW_SIZE (250..1000 ms). Display only.
    pub raw_window: usize,
    pub stream_tx: Option<mpsc::Sender<NeuroPacket>>,
    pub moq_status: Arc<Mutex<String>>,
    pub moq_debug: Arc<Mutex<VecDeque<String>>>,
    pub moq_version: Arc<Mutex<String>>,
    /// now_ms - packet.timestamp_ms: publisher clock vs subscriber clock, so
    /// this is polluted by whatever clock skew exists between the two
    /// machines (same-machine testing has none). Signed so a skewed-behind
    /// subscriber clock shows as a real negative number instead of silently
    /// flooring to a misleading "perfect" 0 — `saturating_sub` used to eat
    /// that case. `jitter_ms` (below) is the trustworthy companion: skew is
    /// ~constant across one ~250ms packet interval, so it mostly cancels out
    /// in the consecutive-reading diff (RFC 3550-style interarrival jitter).
    pub last_latency_ms: i64,
    /// |last_latency_ms - previous last_latency_ms|. Unlike the number above,
    /// this isn't measuring "how old is this packet" — it's "how consistent
    /// is delivery timing," which is what actually predicts a stuttering wave
    /// (a relay delivering groups in bursts, seen before on CF prod). Needs
    /// nothing but the previous reading — no rolling window, no assumed
    /// cadence, no clock sync.
    pub jitter_ms: u64,
    /// QUIC dial + MoQT SETUP handshake duration, refreshed on every
    /// (re)connect — not a continuous ping (see `streaming::StreamingClient::
    /// connect_rtt_ms`).
    pub connect_rtt_ms: Arc<std::sync::atomic::AtomicU64>,
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
            is_subscriber: false,
            synthetic_time: 0.0,
            last_esense_sec: u32::MAX,
            rng: 0x2545F491,
            band_amp: [0.7; 5],
            menu: Menu::Closed,
            menu_cursor: 0,
            sel: streaming::Selection::new(0),
            is_paused: false,
            show_debug: false,
            raw_window: signal_processing::SAMPLE_RATE, // 512 samples = 1000 ms at 512 Hz
            stream_tx: None,
            moq_status: Arc::new(Mutex::new("Offline".to_string())),
            moq_debug: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            moq_version: Arc::new(Mutex::new(String::new())),
            last_latency_ms: 0,
            jitter_ms: 0,
            connect_rtt_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let latency_ms = now_ms - packet.timestamp_ms as i64;
        self.jitter_ms = latency_ms.abs_diff(self.last_latency_ms);
        self.last_latency_ms = latency_ms;

        if !packet.raw_data.is_empty() {
            let new_points = packet
                .raw_data
                .iter()
                .skip(
                    packet
                        .raw_data
                        .len()
                        .saturating_sub(signal_processing::SLIDING_WINDOW_STEP),
                )
                .map(|&x| x as i16);
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
            Relay => RELAYS.len(),
            Transport => TRANSPORTS.len(),
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
                        parser.menu = Relay;
                        parser.menu_cursor = parser.sel.relay.load(Ordering::Relaxed);
                    }
                    1 => {
                        parser.menu = Transport;
                        parser.menu_cursor = parser.sel.transport.load(Ordering::Relaxed);
                    }
                    _ => {}
                },
                Relay => {
                    parser
                        .sel
                        .relay
                        .store(parser.menu_cursor, Ordering::Relaxed);
                    parser.sel.reconfigure.notify_one(); // re-dial the new relay
                    parser.menu = Closed; // selection made — close the popup
                }
                Transport => {
                    parser
                        .sel
                        .transport
                        .store(parser.menu_cursor, Ordering::Relaxed);
                    parser.sel.reconfigure.notify_one(); // re-dial with the new transport
                    parser.menu = Closed; // selection made — close the popup
                }
                Closed => {}
            },
            // Esc / ← backs up a level (or closes from Main).
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => match parser.menu {
                Main => parser.menu = Closed,
                Relay | Transport => {
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
        // Force a fresh redial against the current relay/transport — the same
        // path the M-menu picker already uses (Selection::reconfigure), just
        // triggered without changing the selection. The reconfigure loop only
        // ever redials on its own when the connection itself dies; if it's
        // alive but simply not receiving (a stalled subscribe, an upstream
        // that went quiet), nothing else forces a retry. Subscriber-only: the
        // publisher's loop already redials the moment a write fails.
        KeyCode::Char('r') if parser.is_subscriber => {
            parser.sel.reconfigure.notify_one();
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            parser.raw_window = parser
                .raw_window
                .saturating_sub(SLIDING_WINDOW_STEP)
                .max(SLIDING_WINDOW_STEP);
        }
        KeyCode::Char('-') | KeyCode::Char('_') => {
            parser.raw_window = (parser.raw_window + SLIDING_WINDOW_STEP).min(WINDOW_SIZE);
        }
        _ => {}
    }
    false
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Redirect tracing logs to a sink to prevent TUI corruption from background libraries
    // TUI owns the terminal — tracing goes to the debug log file instead of stdout.
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("neuralkit_debug.log")
        .expect("open neuralkit_debug.log");
    tracing_subscriber::fmt()
        .with_writer(log_file)
        .with_ansi(false)
        .init();

    let args = Args::parse();

    // `neuralkit tray` — hands the main thread to the menu-bar event loop and never
    // comes back (AppKit requires thread 0, which block_on happens to be running on).
    if let Some(Command::Tray { url }) = &args.command {
        #[cfg(target_os = "macos")]
        {
            if let Err(e) = tray::run(url) {
                eprintln!("tray failed: {e:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = url;
            eprintln!("the tray is macOS-only for now");
            std::process::exit(1);
        }
    }

    // `neuralkit auth login` — the passkey QR device flow owns stdout until the
    // token lands, then enters the interactive session (session.rs: the sealed
    // command REPL — NOT the EEG dashboard; that stays the bare-`neuralkit`
    // view, launchable from the session later). Headless callers (the E2E,
    // piped scripts) get sign-in-and-exit: a REPL needs a real terminal.
    if let Some(Command::Auth(AuthCommand::Login { url, qr, totp, passkey, email })) = &args.command {
        // clap already refused both at once, so this is a total mapping: neither flag
        // means "decide at runtime" — ask, or fall to the QR when there is no choice.
        let method = if *qr {
            Some(login::Method::Qr)
        } else if *totp {
            Some(login::Method::Totp)
        } else if *passkey {
            Some(login::Method::Passkey)
        } else if *email {
            Some(login::Method::Email)
        } else {
            None
        };
        if let Err(e) = login::run(url, method).await {
            eprintln!("login failed: {e:#}");
            std::process::exit(1);
        }
        // OFFERED ONCE, WHERE BOTH PATHS MEET. `login::run` returns the same way whether it
        // took the four-call flow or the one-call one, so asking here covers both without the
        // question living in two places. Only when the account has no authenticator — an
        // account that already has one has nothing to answer.
        //
        // This replaces a printed pointer (`setup authenticator? neuralkit auth totp setup`).
        // The pointer was deliberate — it kept a question out of a flow that ends cleanly — but
        // a line of dim text is a path only someone already looking will find, and setup is the
        // one thing a fresh machine most wants next.
        if io::stdout().is_terminal() && io::stdin().is_terminal() && login::totp_enabled() == Some(false) {
            // The SAME picker the sign-in menu uses — arrow keys, one highlighted row — so the
            // two questions this command asks look like one thing. It runs OFF the async
            // runtime for the same reason it does there: crossterm's event::read blocks.
            let header = format!("  {} {}", style::bold("neuralkit"), style::dim("· one more thing"));
            let picked = tokio::task::spawn_blocking(move || {
                login::select(&header, &["set up an authenticator app", "skip — go to the terminal"])
            })
            .await;
            if let Ok(Ok(Some(0))) = picked {
                if let Err(e) = totp::setup(url).await {
                    // Not fatal: the sign-in already succeeded, and setup can be run again by
                    // name. Ending the session over a declined or mistyped code would throw
                    // away the thing that worked.
                    eprintln!("  totp setup failed: {e:#}");
                }
            }
        }

        if io::stdout().is_terminal() && io::stdin().is_terminal() {
            // The REPL and the dashboard take turns owning the terminal: `dash` returns
            // rather than launching, the dashboard runs with the REPL fully out of the
            // way, and quitting it (Q) lands back at a fresh prompt — reconnected, since
            // the sealed channel was closed on the way out.
            loop {
                match session::run().await {
                    Ok(session::Next::Dash) => {
                        if let Err(e) = run_dashboard(&args).await {
                            // The dashboard restores the terminal on its own error paths;
                            // this is insurance so a failure can't strand the REPL in raw
                            // mode with no prompt.
                            let _ = disable_raw_mode();
                            eprintln!("  dashboard error: {e:#}");
                        }
                    }
                    Ok(session::Next::Done) => break,
                    Err(e) => {
                        eprintln!("session error: {e:#}");
                        std::process::exit(1);
                    }
                }
            }
        }
        return Ok(());
    }

    if let Some(Command::Auth(AuthCommand::Passkey { action, url })) = &args.command {
        let outcome = match action {
            Some(PasskeyAction::Register { url }) => passkey::register(url, false).await,
            Some(PasskeyAction::Login { url }) => passkey::login(url).await,
            #[cfg(target_os = "macos")]
            Some(PasskeyAction::System { url }) => passkey::system(url).await,
            #[cfg(not(target_os = "macos"))]
            Some(PasskeyAction::System { .. }) => Err(anyhow::anyhow!("the system passkey store is macOS-only")),
            None => passkey::run(url),
        };
        if let Err(e) = outcome {
            eprintln!("passkey failed: {e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Some(Command::Auth(AuthCommand::Totp(TotpAction::Setup { url }))) = &args.command {
        if let Err(e) = totp::setup(url).await {
            eprintln!("totp setup failed: {e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Some(Command::Auth(AuthCommand::Unregister)) = &args.command {
        if let Err(e) = login::unregister().await {
            eprintln!("unregister failed: {e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    run_dashboard(&args).await
}

/// The TUI dashboard — extracted from `main`'s tail so the REPL's `dash` command opens
/// the SAME thing bare `neuralkit` runs, with the same args the process started with.
/// Owns the whole terminal (raw mode + alternate screen) for its lifetime; every exit
/// path restores it, which is what lets a REPL prompt survive on the other side.
async fn run_dashboard(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = BrainWaveParser::new();
    parser.synthetic = args.synthetic;
    parser.is_subscriber = args.sub;

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
        client.connect_rtt_ms = parser.connect_rtt_ms.clone();
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
        client.connect_rtt_ms = parser.connect_rtt_ms.clone();
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
    // Fractional-sample carry: the subscriber drains SAMPLE_RATE*elapsed samples
    // per frame, but truncating to usize each tick loses ~1 sample/frame, so the
    // smoothing buffer (and thus the lag) creeps up over time. Carry the remainder
    // so the drain matches the arrival rate exactly and the buffer stays shallow.
    let mut drain_acc: f64 = 0.0;
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
                // Apply any waiting packet, but don't block the frame on one: wake
                // every ~8ms so the 33ms draw tick fires at a steady ~30fps. Waiting
                // the full tick_rate here for a packet coupled the frame rate to the
                // 4Hz packet arrival, dropping the whole dashboard to ~21fps.
                tokio::select! {
                    Some(packet) = rx_packets.recv() => {
                        parser.apply_packet(packet);
                        while let Ok(packet) = rx_packets.try_recv() {
                            parser.apply_packet(packet);
                        }
                    }
                    _ = tokio::time::sleep(tick_rate.saturating_sub(last_tick.elapsed())) => {}
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

        // Pump input BEFORE the drain/draw so a keypress takes effect on the same
        // frame. If P (pause) were only caught after the drain, the --sub wave
        // would advance one extra frame before freezing ("plays a little").
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

        if last_tick.elapsed() >= tick_rate {
            // Gate the smoothing-drain on !is_paused (the receive stage already is),
            // so P freezes the raw wave + attention/meditation immediately — same as
            // the bands. The smoothing itself is untouched: it only stops WHILE
            // paused. terminal.draw stays outside, so the frozen frame still renders
            // and the TUI stays responsive.
            if args.sub && !parser.is_paused {
                drain_acc +=
                    signal_processing::SAMPLE_RATE as f64 * last_tick.elapsed().as_secs_f64();
                let base = drain_acc as usize;
                drain_acc -= base as f64;
                // Gentle clock-recovery: also drain 10% of any excess beyond one
                // packet each frame, so a small pub/sub rate drift can't let the lag
                // creep up. Steers the buffer to ~1 packet (~250 ms) smoothly,
                // without the periodic drop-stutter a hard cap would cause.
                let target = signal_processing::SLIDING_WINDOW_STEP;
                let steer = parser.raw_buffer.len().saturating_sub(target) / 6;
                let samples_to_pop = base + steer;
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

                // Keep the smoothing buffer SHALLOW (a couple of packets) so the
                // subscriber tracks the publisher in near-real-time. This is what
                // makes a pause match: when the publisher's playhead stops, the
                // stream stops, and the subscriber drains this short buffer to the
                // publisher's LAST sent frame within ~0.5s and freezes there — the
                // two paused screens line up, instead of the subscriber replaying a
                // multi-second backlog. A larger buffer only adds latency + drift.
                const BUF_CAP: usize = 2 * signal_processing::SLIDING_WINDOW_STEP; // 256 ≈ 0.5s (ceiling)
                const BUF_KEEP: usize = signal_processing::SLIDING_WINDOW_STEP; // 128 ≈ 0.25s (one packet: the 4 Hz smoothing floor)
                if parser.raw_buffer.len() > BUF_CAP {
                    let excess = parser.raw_buffer.len() - BUF_KEEP;
                    parser.raw_buffer.drain(0..excess);
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

            // Reset the tick BEFORE drawing (the drain above already consumed the
            // elapsed time). Resetting after the draw made the frame period
            // tick_rate + draw_time (~48ms → ~21fps); measuring from draw-start
            // gives a steady ~30fps as long as a draw fits inside tick_rate.
            last_tick = Instant::now();
            terminal.draw(|f| tui::render_dashboard(f, &parser))?;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    // Graceful quit: tell the streaming task to close its relay session, then give
    // quinn a moment to transmit the CONNECTION_CLOSE before the process exits — so
    // phaze-relay reaps the session at once instead of waiting the QUIC idle timeout.
    sel.shutdown.notify_one();
    tokio::time::sleep(Duration::from_millis(400)).await;

    Ok(())
}
