// MoQ streaming on the moq-dev lineage (moq-net + moq-native), modeled EXACTLY
// on moq-native's examples/clock.rs (the validated pattern: clock pub/sub runs
// green against the local relay). Ported from the IETF moq-transport crates
// 2026-07-13 so browser subscribers (@moq/net, moq-lite) can consume the same
// broadcast — moq-net negotiates moq-lite with the relay.
use anyhow::{Context, Result};
use moq_net::{Broadcast, Origin, Path, Track};
use tokio::sync::mpsc;
use url::Url;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/neuralkit.rs"));
    pub mod tak {
        include!(concat!(env!("OUT_DIR"), "/atakmap.commoncommo.protobuf.v1.rs"));
    }
}
pub use proto::NeuroPacket;
pub use proto::tak::{TakMessage, CotEvent, CotDetail};
use prost::Message;

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

/// Live-selectable relay + protocol, shared between the dashboard (which mutates
/// it from the `M` menu) and the connection task (which reads it each dial). A
/// change + `reconfigure.notify_one()` makes the task drop its client and
/// re-dial with the new URL/ALPN — the picker is live.
#[derive(Clone)]
pub struct Selection {
    pub relay: Arc<AtomicUsize>,
    pub protocol: Arc<AtomicUsize>,
    pub reconfigure: Arc<Notify>,
}

impl Selection {
    pub fn new(relay: usize) -> Self {
        Self {
            relay: Arc::new(AtomicUsize::new(relay)),
            protocol: Arc::new(AtomicUsize::new(0)),
            reconfigure: Arc::new(Notify::new()),
        }
    }
    /// The currently-selected relay URL (from the RELAYS table).
    fn url(&self) -> Result<Url> {
        let i = self.relay.load(Ordering::Relaxed).min(crate::RELAYS.len() - 1);
        Url::parse(crate::RELAYS[i].1).context("invalid relay URL")
    }
    fn protocol_idx(&self) -> usize {
        self.protocol.load(Ordering::Relaxed)
    }
}

/// Build a moq-native client dialing `url`, cert verification disabled for the
/// self-signed local relay. `protocol_idx` (0 = Auto) forces a single ALPN.
fn moq_client(url: &Url, protocol_idx: usize) -> Result<moq_native::Client> {
    let mut config = moq_native::ClientConfig::default();
    config.connect = Some(url.clone());
    if matches!(url.host_str(), Some("localhost") | Some("127.0.0.1")) {
        config.tls.disable_verify = Some(true);
    }
    // Force one protocol when the picker isn't on "Auto" (offer-all).
    if protocol_idx > 0 {
        if let Some(v) = crate::PROTOCOLS.get(protocol_idx).and_then(|n| n.parse().ok()) {
            config.version = vec![v];
        }
    }
    config.init().context("moq client init failed")
}

pub struct StreamingClient {
    pub url: Url,
    pub path: String,
    pub status: Arc<Mutex<String>>,
    pub debug: Arc<Mutex<VecDeque<String>>>,
    pub sel: Selection,
}

impl StreamingClient {
    pub fn new(url: &str, path: &str) -> Result<Self> {
        let url = Url::parse(url).context("Invalid MoQ relay URL")?;
        Ok(Self {
            url,
            path: path.to_string(),
            status: Arc::new(Mutex::new("Initializing".to_string())),
            debug: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            sel: Selection::new(0),
        })
    }

    fn add_debug(&self, msg: &str) {
        if let Ok(mut d) = self.debug.lock() {
            let msg = if msg.len() > 100 { format!("{}...", &msg[..97]) } else { msg.to_string() };
            d.push_back(msg);
            if d.len() > 100 { d.pop_front(); }
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

        // Reconfigure loop: (re)dial whenever the relay/protocol selection changes
        // (M-menu) or the session drops, so the picker is live.
        loop {
            let url = self.sel.url()?;
            let proto = self.sel.protocol_idx();
            self.set_status(&format!(
                "Connecting to {}...",
                url.host_str().unwrap_or("relay")
            ));
            let client = match moq_client(&url, proto) {
                Ok(c) => c,
                Err(e) => {
                    self.set_status(&format!("Client init failed: {}", e));
                    tokio::select! {
                        _ = self.sel.reconfigure.notified() => {}
                        _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                    }
                    continue;
                }
            };

            // clock.rs order: create the track FIRST, publish the broadcast into
            // the origin AFTER, then hand the origin to client.publish.
            let origin = Origin::random().produce();
            let mut broadcast = Broadcast::new().produce();
            let mut track = broadcast
                .create_track(Track::new(TRACK_NAME))
                .map_err(|e| anyhow::anyhow!("Track create failed: {:?}", e))?;
            // "eeg" = browser-native FlatBuffer twin of track "0" (protobuf).
            let mut eeg_track = broadcast
                .create_track(Track::new(EEG_TRACK_NAME))
                .map_err(|e| anyhow::anyhow!("Track create failed: {:?}", e))?;
            origin.publish_broadcast(&path_clean, broadcast.consume());

            let reconnect = client
                .publish(origin.consume())
                .context("no connect URL configured")?;
            self.set_status(&format!("Online (Publishing {})", path_clean));

            loop {
                tokio::select! {
                    _ = self.sel.reconfigure.notified() => {
                        self.set_status("Switching relay/protocol...");
                        break;
                    }
                    res = reconnect.closed() => {
                        self.set_status(&format!("Offline: {:?}; retrying", res));
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break;
                    }
                    Some(packet) = rx.recv() => {
                        let mut buf = Vec::new();
                        packet.encode(&mut buf)?;
                        // One single-frame group per packet — each NeuroPacket is
                        // independently deliverable (chat.rs's write_frame helper).
                        track.write_frame(buf).map_err(|e| anyhow::anyhow!("Write error: {:?}", e))?;

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
                        eeg_track.write_frame(fbb.finished_data().to_vec())
                            .map_err(|e| anyhow::anyhow!("Write error: {:?}", e))?;
                    }
                    else => return Ok(()),
                }
            }
        }
    }
}

pub struct SubscriberClient {
    pub url: Url,
    pub path: String,
    pub status: Arc<Mutex<String>>,
    pub debug: Arc<Mutex<VecDeque<String>>>,
    pub net_latency_ms: Arc<std::sync::atomic::AtomicU64>,
    pub sel: Selection,
}

impl SubscriberClient {
    pub fn new(url: &str, path: &str) -> Result<Self> {
        let url = Url::parse(url).context("Invalid MoQ relay URL")?;
        Ok(Self {
            url,
            path: path.to_string(),
            status: Arc::new(Mutex::new("Initializing".to_string())),
            debug: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            net_latency_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sel: Selection::new(0),
        })
    }

    fn add_debug(&self, msg: &str) {
        if let Ok(mut d) = self.debug.lock() {
            d.push_back(msg.to_string());
            if d.len() > 100 { d.pop_front(); }
        }
    }

    fn set_status(&self, msg: &str) {
        self.add_debug(msg);
        if let Ok(mut s) = self.status.lock() {
            *s = msg.to_string();
        }
    }

    pub async fn run(self, tx: mpsc::Sender<NeuroPacket>) -> Result<()> {
        let url = self.sel.url()?;
        let host_name = url.host_str().unwrap_or("relay").to_string();
        let port = url.port().unwrap_or(443);
        let net_lat = self.net_latency_ms.clone();

        // Background task to ping the host every 2 seconds
        tokio::spawn(async move {
            loop {
                let start = std::time::Instant::now();
                if let Ok(Ok(_)) = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::net::TcpStream::connect((host_name.as_str(), port)),
                ).await {
                    let rtt = start.elapsed().as_millis() as u64;
                    net_lat.store(rtt, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        self.set_status("Configuring Network...");
        let client = moq_client(&url, self.sel.protocol_idx())?;

        let path_clean = self.path.trim_start_matches('/').trim_end_matches('/').to_string();

        // clock.rs subscribe pattern: hand the origin PRODUCER to client.consume so
        // the relay fills it with announces; scope a consumer to the broadcast path;
        // loop on announced() and subscribe_track on the online broadcast.
        let origin = Origin::random().produce();
        let reconnect = client
            .consume(origin.clone())
            .context("no connect URL configured")?;

        let path: Path = path_clean.as_str().into();
        let mut origin = origin
            .scope(&[path])
            .context("not allowed to consume broadcast")?
            .consume();

        self.set_status(&format!("Subscribing to: {}...", path_clean));

        loop {
            tokio::select! {
                res = reconnect.closed() => {
                    let err = format!("Session closed: {:?}", res);
                    self.set_status(&format!("Offline: {}", err));
                    return Err(anyhow::anyhow!(err));
                }
                Some(announce) = origin.announced() => match announce {
                    (p, Some(broadcast)) => {
                        self.set_status(&format!("Online (Subscribing {})", p));
                        let mut track = broadcast
                            .subscribe_track(&Track::new(TRACK_NAME))
                            .map_err(|e| anyhow::anyhow!("Subscribe error: {:?}", e))?;
                        let tx = tx.clone();
                        // Drain groups on a task so a new announce doesn't block the loop.
                        tokio::spawn(async move {
                            while let Ok(Some(mut group)) = track.recv_group().await {
                                while let Ok(Some(frame)) = group.read_frame().await {
                                    if let Ok(packet) = NeuroPacket::decode(frame) {
                                        // Headless visibility: the TUI owns the terminal, so
                                        // the received-packet count goes to the tracing log.
                                        static PKT_COUNT: std::sync::atomic::AtomicU64 =
                                            std::sync::atomic::AtomicU64::new(0);
                                        let n = PKT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                        if n == 1 || n % 100 == 0 {
                                            tracing::info!(n, "subscriber packets received");
                                        }
                                        let _ = tx.send(packet).await;
                                    }
                                }
                            }
                        });

                        // Same broadcast, the eeg FlatBuffer track — independent
                        // subscribe + counter, verifying the producer side of the
                        // Neuralkit.eeg fence without touching the TUI's own data path.
                        let mut eeg_track = broadcast
                            .subscribe_track(&Track::new(EEG_TRACK_NAME))
                            .map_err(|e| anyhow::anyhow!("Subscribe error: {:?}", e))?;
                        tokio::spawn(async move {
                            while let Ok(Some(mut group)) = eeg_track.recv_group().await {
                                while let Ok(Some(frame)) = group.read_frame().await {
                                    if let Ok(nf) = root_as_neuro_frame(&frame) {
                                        static EEG_COUNT: std::sync::atomic::AtomicU64 =
                                            std::sync::atomic::AtomicU64::new(0);
                                        let n = EEG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                        if n == 1 || n % 100 == 0 {
                                            let raw_len = nf.raw_data().map(|v| v.len()).unwrap_or(0);
                                            tracing::info!(n, seq = nf.seq(), poor_signal = nf.poor_signal(), raw_len, "eeg subscriber frames received");
                                        }
                                    }
                                }
                            }
                        });
                    }
                    (p, None) => {
                        self.set_status(&format!("Broadcast offline: {}", p));
                    }
                },
            }
        }
    }
}
