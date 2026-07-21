// MoQ streaming on Cloudflare's own moq-transport/moq-native-ietf (via
// phaze-moq), not Luke Curley's moq-net. Cloudflare's production relay
// (draft-ietf-moq-transport-07) has no announce/discovery at all — confirmed
// straight from their own producer.rs: "there's no announce/discovery
// forwarding. The producer passively responds to subscription requests." A
// subscriber must know the exact namespace/track name and SUBSCRIBE directly.
// phaze-moq's Subscriber does exactly that natively — no announce step
// anywhere in this file, on either the publish or subscribe side.
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tokio::sync::mpsc;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/neuralkit.rs"));
    pub mod tak {
        include!(concat!(
            env!("OUT_DIR"),
            "/atakmap.commoncommo.protobuf.v1.rs"
        ));
    }
}
use prost::Message;
pub use proto::NeuroPacket;
pub use proto::tak::{CotDetail, CotEvent, TakMessage};

// The eeg-track FlatBuffer encoding — a DELIBERATELY MINIMAL twin of NeuroPacket
// (seq/raw_data/poor_signal only), byte-compatible with neuralkit-web's ALREADY-
// SHIPPED browser reader (src/transport/flat_schema/eeg/neuro-frame.ts) — see
// src/proto/neuro.fbs for why field order is load-bearing (vtable slots).
pub mod fb {
    include!(concat!(env!("OUT_DIR"), "/neuro_generated.rs"));
}
pub use fb::neuralkit::fb::{NeuroFrame, NeuroFrameArgs, root_as_neuro_frame};

const TRACK_NAME: &str = "0";
const EEG_TRACK_NAME: &str = "eeg";

/// Live-selectable relay + transport, shared between the dashboard (which
/// mutates it from the `M` menu) and the connection task (which reads it each
/// dial). A change + `reconfigure.notify_one()` makes the task drop its
/// connection and re-dial with the new selection — both pickers are live.
///
/// No wire-protocol picker — phaze-moq speaks exactly one wire (Cloudflare's
/// moq-transport, draft-16). `transport` only picks WebTransport vs raw QUIC,
/// two real code paths moq-native-ietf already has for that one wire.
#[derive(Clone)]
pub struct Selection {
    pub relay: Arc<AtomicUsize>,
    pub transport: Arc<AtomicUsize>,
    pub reconfigure: Arc<Notify>,
    /// Signalled on quit so the streaming task drops its connection and lets
    /// the relay reap the session immediately (graceful CONNECTION_CLOSE)
    /// instead of waiting out the QUIC idle timeout.
    pub shutdown: Arc<Notify>,
}

impl Selection {
    pub fn new(relay: usize) -> Self {
        Self {
            relay: Arc::new(AtomicUsize::new(relay)),
            transport: Arc::new(AtomicUsize::new(0)),
            reconfigure: Arc::new(Notify::new()),
            shutdown: Arc::new(Notify::new()),
        }
    }
    /// The currently-selected relay URL (from the RELAYS table).
    fn url(&self) -> String {
        let i = self
            .relay
            .load(Ordering::Relaxed)
            .min(crate::RELAYS.len() - 1);
        crate::RELAYS[i].1.to_string()
    }
    /// The currently-selected transport (from the TRANSPORTS table).
    fn transport(&self) -> phaze_moq::Transport {
        let i = self
            .transport
            .load(Ordering::Relaxed)
            .min(crate::TRANSPORTS.len() - 1);
        crate::TRANSPORTS[i].1
    }
}

/// Pull `(host, port)` out of a relay URL string for the "Connecting to..."
/// status line. `phaze_moq` takes the URL as a bare `&str`, so this is the
/// one place we still parse it — display only, never the connect path itself.
fn host_port(url: &str) -> (String, u16) {
    url::Url::parse(url)
        .ok()
        .map(|u| {
            (
                u.host_str().unwrap_or("relay").to_string(),
                u.port().unwrap_or(443),
            )
        })
        .unwrap_or_else(|| ("relay".to_string(), 443))
}

/// `insecure`: skip TLS verification. On for loopback (phaze-relay's
/// self-signed `--local` dev cert) and for `*.mediaoverquic.com` (Cloudflare's
/// interop relay currently serves an expired cert — production's is real, but
/// bypassing verification for the whole domain is harmless and one less thing
/// to keep in sync if that ever changes).
fn is_insecure(url: &str) -> bool {
    matches!(
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .as_deref(),
        Some("localhost") | Some("127.0.0.1")
    ) || url.contains("mediaoverquic.com")
}

pub struct StreamingClient {
    pub url: String,
    pub path: String,
    pub status: Arc<Mutex<String>>,
    pub debug: Arc<Mutex<VecDeque<String>>>,
    /// Display-only; moq-transport doesn't expose a negotiated-version
    /// concept the way moq-net did (it speaks exactly one wire), so this is
    /// just a fixed label once connected — kept so the dashboard's layout
    /// doesn't need to change.
    pub version: Arc<Mutex<String>>,
    /// QUIC dial + MoQT SETUP handshake duration, refreshed on every
    /// (re)connect. Not a live ping — see `phaze_moq::Publisher::connect_rtt`
    /// for why a continuous one isn't achievable without forking.
    pub connect_rtt_ms: Arc<AtomicU64>,
    pub sel: Selection,
}

impl StreamingClient {
    pub fn new(url: &str, path: &str) -> Result<Self> {
        Ok(Self {
            url: url.to_string(),
            path: path.to_string(),
            status: Arc::new(Mutex::new("Initializing".to_string())),
            debug: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            version: Arc::new(Mutex::new(String::new())),
            connect_rtt_ms: Arc::new(AtomicU64::new(0)),
            sel: Selection::new(0),
        })
    }

    fn add_debug(&self, msg: &str) {
        if let Ok(mut d) = self.debug.lock() {
            d.push_back(msg.to_string());
            if d.len() > 100 {
                d.pop_front();
            }
        }
    }

    fn set_status(&self, msg: &str) {
        self.add_debug(msg);
        if let Ok(mut s) = self.status.lock() {
            *s = msg.to_string();
        }
    }

    pub async fn run(self, mut rx: mpsc::Receiver<NeuroPacket>) -> Result<()> {
        let path_clean = self
            .path
            .trim_start_matches('/')
            .trim_end_matches('/')
            .to_string();
        if path_clean.is_empty() {
            anyhow::bail!("Stream path cannot be empty");
        }
        let mut eeg_seq: u32 = 0;

        // Reconfigure loop: (re)dial whenever the relay selection changes (M
        // menu) or the session drops, so the picker is live.
        loop {
            let url = self.sel.url();
            self.set_status(&format!("Connecting to {}", host_port(&url).0));

            let mut publisher =
                match phaze_moq::Publisher::connect(&url, is_insecure(&url), self.sel.transport())
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        self.set_status(&format!("Client init failed: {}", e));
                        tokio::select! {
                            _ = self.sel.reconfigure.notified() => {}
                            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                        }
                        continue;
                    }
                };
            self.connect_rtt_ms.store(
                publisher.connect_rtt().as_millis() as u64,
                Ordering::Relaxed,
            );

            // One announce for the namespace; both tracks come off the SAME
            // broadcast handle — creating two independent announces (one per
            // track) means a subscriber looking up the "0" announce for the
            // "eeg" track (or vice versa) gets "not found", even though both
            // were genuinely announced moments apart.
            let mut broadcast = match publisher.announce(&path_clean).await {
                Ok(b) => b,
                Err(e) => {
                    self.set_status(&format!("Announce failed: {}", e));
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let mut track = match broadcast.create_track(TRACK_NAME) {
                Ok(t) => t,
                Err(e) => {
                    self.set_status(&format!("Track create failed: {}", e));
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            // "eeg" = browser-native FlatBuffer twin of track "0" (protobuf).
            let mut eeg_track = match broadcast.create_track(EEG_TRACK_NAME) {
                Ok(t) => t,
                Err(e) => {
                    self.set_status(&format!("Track create failed: {}", e));
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };

            self.set_status(&format!("Online (Publishing {})", path_clean));
            if let Ok(mut v) = self.version.lock() {
                *v = "moq-transport".to_string();
            }

            let mut quitting = false;
            loop {
                tokio::select! {
                    _ = self.sel.shutdown.notified() => {
                        quitting = true;
                        break;
                    }
                    _ = self.sel.reconfigure.notified() => {
                        self.set_status("Switching relay");
                        break;
                    }
                    _ = publisher.closed() => {
                        self.set_status("Offline; retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break;
                    }
                    Some(packet) = rx.recv() => {
                        let mut buf = Vec::new();
                        packet.encode(&mut buf)?;
                        // One frame (its own group) per packet — each NeuroPacket
                        // is independently deliverable.
                        if let Err(e) = track.write_frame(buf.into()) {
                            self.set_status(&format!("Offline: {:?}; retrying", e));
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            break;
                        }

                        // Same packet, FB-encoded onto "eeg" with a monotonic seq.
                        let mut fbb = flatbuffers::FlatBufferBuilder::new();
                        let raw_data = fbb.create_vector(&packet.raw_data);
                        let frame = NeuroFrame::create(&mut fbb, &NeuroFrameArgs {
                            seq: eeg_seq,
                            raw_data: Some(raw_data),
                            poor_signal: packet.poor_signal as u8,
                        });
                        fbb.finish(frame, None);
                        eeg_seq = eeg_seq.wrapping_add(1);
                        if let Err(e) = eeg_track.write_frame(bytes::Bytes::copy_from_slice(fbb.finished_data())) {
                            self.set_status(&format!("Offline: {:?}; retrying", e));
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            break;
                        }
                    }
                    else => return Ok(()),
                }
            }
            if quitting {
                // Dropping `publisher` closes its session (CONNECTION_CLOSE);
                // give quinn a moment to actually transmit it before exit, so
                // the relay reaps us at once instead of on the idle timeout.
                drop(publisher);
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                return Ok(());
            }
        }
    }
}

pub struct SubscriberClient {
    pub url: String,
    pub path: String,
    pub status: Arc<Mutex<String>>,
    pub debug: Arc<Mutex<VecDeque<String>>>,
    pub version: Arc<Mutex<String>>,
    /// See `StreamingClient::connect_rtt_ms`.
    pub connect_rtt_ms: Arc<AtomicU64>,
    pub sel: Selection,
}

impl SubscriberClient {
    pub fn new(url: &str, path: &str) -> Result<Self> {
        Ok(Self {
            url: url.to_string(),
            path: path.to_string(),
            status: Arc::new(Mutex::new("Initializing".to_string())),
            debug: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            version: Arc::new(Mutex::new(String::new())),
            connect_rtt_ms: Arc::new(AtomicU64::new(0)),
            sel: Selection::new(0),
        })
    }

    fn add_debug(&self, msg: &str) {
        if let Ok(mut d) = self.debug.lock() {
            d.push_back(msg.to_string());
            if d.len() > 100 {
                d.pop_front();
            }
        }
    }

    fn set_status(&self, msg: &str) {
        self.add_debug(msg);
        if let Ok(mut s) = self.status.lock() {
            *s = msg.to_string();
        }
    }

    pub async fn run(self, tx: mpsc::Sender<NeuroPacket>) -> Result<()> {
        let path_clean = self
            .path
            .trim_start_matches('/')
            .trim_end_matches('/')
            .to_string();

        // Reconfigure loop: (re)dial whenever the relay selection changes (M
        // menu) or the session drops, so the picker is live on --sub too.
        loop {
            let url = self.sel.url();
            self.set_status(&format!("Connecting to {}", host_port(&url).0));

            let mut subscriber =
                match phaze_moq::Subscriber::connect(&url, is_insecure(&url), self.sel.transport())
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        self.set_status(&format!("Client init failed: {}", e));
                        tokio::select! {
                            _ = self.sel.reconfigure.notified() => {}
                            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                        }
                        continue;
                    }
                };
            self.connect_rtt_ms.store(
                subscriber.connect_rtt().as_millis() as u64,
                Ordering::Relaxed,
            );

            self.set_status(&format!("Subscribing to: {}", path_clean));

            // Direct subscribe by name — no announce, no discovery. Resolves
            // once the relay/publisher acknowledges (SUBSCRIBE_OK); if the
            // broadcast isn't live yet this fails fast and the outer loop
            // retries, same as a dropped connection.
            let mut track = match subscriber.subscribe(&path_clean, TRACK_NAME).await {
                Ok(t) => t,
                Err(e) => {
                    self.set_status(&format!("Broadcast offline: {} ({})", path_clean, e));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
            let mut eeg_track = match subscriber.subscribe(&path_clean, EEG_TRACK_NAME).await {
                Ok(t) => t,
                Err(e) => {
                    self.set_status(&format!("Broadcast offline: {} ({})", path_clean, e));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            self.set_status(&format!("Online (Subscribing {})", path_clean));
            if let Ok(mut v) = self.version.lock() {
                *v = "moq-transport".to_string();
            }

            {
                let tx = tx.clone();
                tokio::spawn(async move {
                    static PKT_COUNT: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    while let Ok(Some(frame)) = track.read_frame().await {
                        if let Ok(packet) = NeuroPacket::decode(frame) {
                            let n =
                                PKT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            if n == 1 || n % 100 == 0 {
                                tracing::info!(n, "subscriber packets received");
                            }
                            let _ = tx.send(packet).await;
                        }
                    }
                });
            }
            // Same broadcast, the eeg FlatBuffer track — independent read +
            // counter, verifying the producer side of the Neuralkit.eeg fence
            // without touching the TUI's own data path.
            tokio::spawn(async move {
                static EEG_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                while let Ok(Some(frame)) = eeg_track.read_frame().await {
                    if let Ok(nf) = root_as_neuro_frame(&frame) {
                        let n = EEG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        if n == 1 || n % 100 == 0 {
                            let raw_len = nf.raw_data().map(|v| v.len()).unwrap_or(0);
                            tracing::info!(
                                n,
                                seq = nf.seq(),
                                poor_signal = nf.poor_signal(),
                                raw_len,
                                "eeg subscriber frames received"
                            );
                        }
                    }
                }
            });

            let mut quitting = false;
            tokio::select! {
                _ = self.sel.shutdown.notified() => { quitting = true; }
                _ = self.sel.reconfigure.notified() => { self.set_status("Switching relay"); }
                _ = subscriber.closed() => {
                    self.set_status("Offline; retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            if quitting {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                return Ok(());
            }
            // reconfigure or a dead connection → loop, drop `subscriber` (its
            // Drop closes the session), and re-dial.
        }
    }
}
