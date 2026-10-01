//! Bluetooth headsets as a dashboard source: finding one, pairing it, and reading its channel.
//! The bytes go into an `mpsc` channel, the way `--sub`'s packets do, and the dashboard loop
//! drains it without waiting. The Headset panel (`M` › Headset) searches and lists; the loop owns
//! the search, the pairing and the connection, and reports each through a `poll`.
//!
//! NO DEVICE IS NAMED HERE. A headset is whatever the search finds or macOS has paired, chosen in
//! the panel; the channel is whichever its service records name; the PIN is typed by the person.
//!
//! THE PORT FILE DOES NOT CARRY IT. macOS lists a paired serial device as `/dev/cu.<name>`, but
//! opening that file did not connect the headset (measured 2026-10-01 on the NeuroSky: 0 bytes,
//! blocking or not, with the link already up). Opening the device's RFCOMM channel through
//! IOBluetooth does — the same ThinkGear frames the dongle delivers, ~512 raw samples a second.
//!
//! ON THE MAIN THREAD. IOBluetooth refused an open on a background thread running its own run
//! loop (0xe00002bc, twice) and accepted it on the main one, and it calls every delegate here
//! during a turn of that run loop. `#[tokio::main]` polls `main`'s future — and `run_dashboard`
//! with it — on the main thread, so the loop starts each operation there and `pump`s once a
//! frame, as phaze-auth's `system_passkey::assert` pumps for its sheet. Nothing here waits: every
//! operation completes in a later pump, so the dashboard never stalls on the radio.
//!
//! IN PACKETS. The headset's link delivers ~208 bytes (~26 raw samples) at a time, ~20 a second,
//! with gaps up to ~170 ms (measured over 60 s); the dongle delivers ~34 bytes every ~6 ms. Same
//! frames, none lost — which is why nothing here waits for them.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::io;
use std::time::{Duration, Instant};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol};
use objc2::{define_class, msg_send, AllocAnyThread, DefinedClass};
use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop, CFRunLoopRunResult};
use objc2_foundation::NSString;
use objc2_io_bluetooth::{
    kBluetoothDeviceClassMajorAudio, BluetoothPINCode, IOBluetoothDevice, IOBluetoothDeviceInquiry,
    IOBluetoothDeviceInquiryDelegate, IOBluetoothDevicePair, IOBluetoothDevicePairDelegate,
    IOBluetoothRFCOMMChannel, IOBluetoothRFCOMMChannelDelegate, IOBluetoothSDPServiceRecord,
};
use tokio::sync::mpsc::UnboundedSender;

// ── The channel ──────────────────────────────────────────────────────────────

/// What the delegate has seen of one open: its result once it completes, whether the headset
/// has closed the channel since, and the dashboard's channel for the bytes.
struct Seen {
    tx: RefCell<Option<UnboundedSender<Vec<u8>>>>,
    opened: Cell<Option<i32>>,
    closed: Cell<bool>,
}

define_class!(
    /// One open's delegate — the source's producer. Each chunk goes into the dashboard's channel.
    #[unsafe(super(NSObject))]
    #[name = "NKHeadsetChannel"]
    #[ivars = Seen]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl IOBluetoothRFCOMMChannelDelegate for Delegate {
        #[unsafe(method(rfcommChannelData:data:length:))]
        fn data(&self, _channel: Option<&IOBluetoothRFCOMMChannel>, data: *mut c_void, length: usize) {
            if data.is_null() { return }
            // SAFETY: IOBluetooth passes `length` readable bytes at `data` for this call.
            let chunk = unsafe { std::slice::from_raw_parts(data as *const u8, length) };
            if let Some(tx) = self.ivars().tx.borrow().as_ref() {
                let _ = tx.send(chunk.to_vec());
            }
        }

        #[unsafe(method(rfcommChannelOpenComplete:status:))]
        fn open_complete(&self, _channel: Option<&IOBluetoothRFCOMMChannel>, status: i32) {
            self.ivars().opened.set(Some(status));
        }

        #[unsafe(method(rfcommChannelClosed:))]
        fn closed(&self, _channel: Option<&IOBluetoothRFCOMMChannel>) {
            self.ivars().closed.set(true);
            self.ivars().tx.borrow_mut().take();
        }
    }
);

impl Delegate {
    fn new(tx: UnboundedSender<Vec<u8>>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(Seen {
            tx: RefCell::new(Some(tx)),
            opened: Cell::new(None),
            closed: Cell::new(false),
        });
        unsafe { msg_send![super(this), init] }
    }
}

/// Where a headset's channel stands, read once a frame by the dashboard loop.
pub enum Link {
    /// Reading its service records, to learn which channel to open.
    Reading,
    Opening,
    Open,
    Closed,
    Failed(String),
}

/// A headset's channel, opening or open. Dropping it closes the channel and the link.
pub struct Headset {
    device: Retained<IOBluetoothDevice>,
    /// Channels not tried yet, lowest first (the NeuroSky: its ThinkGear stream on 1, a
    /// "WeChat" service on 23).
    untried: Vec<u8>,
    /// Set while the service records are being read — a device paired just now has none stored.
    reading: Option<Instant>,
    /// The dashboard's channel, kept for the next attempt until one opens.
    tx: Option<UnboundedSender<Vec<u8>>>,
    current: Option<(Retained<IOBluetoothRFCOMMChannel>, Retained<Delegate>)>,
    /// When the current attempt was asked for — see `OPEN_DEADLINE`.
    asked: Instant,
    last_status: i32,
    /// Why it gave up, once it has; `poll` keeps reporting it.
    failed: Option<String>,
}

/// How long an open may stay unanswered. IOBluetooth never answers an asynchronous open to a
/// headset it cannot reach — measured with the NeuroSky switched off: no completion and no close
/// in 40 s, whether the run loop was pumped or run without pause — while the synchronous open
/// gave up after 15.4 s. So the deadline is that one.
const OPEN_DEADLINE: Duration = Duration::from_secs(15);

/// How long reading a device's service records may take before it counts as offering none.
const READ_DEADLINE: Duration = Duration::from_secs(10);

fn paired() -> Vec<Retained<IOBluetoothDevice>> {
    let Some(devices) = (unsafe { IOBluetoothDevice::pairedDevices() }) else { return Vec::new() };
    devices.iter().filter_map(|d| d.downcast::<IOBluetoothDevice>().ok()).collect()
}

/// The RFCOMM channels the device's service records name, lowest first — as macOS stored them
/// from the last read; nothing goes over the air.
fn channels(device: &IOBluetoothDevice) -> Vec<u8> {
    let Some(records) = (unsafe { device.services() }) else { return Vec::new() };
    let mut ids: Vec<u8> = records
        .iter()
        .filter_map(|r| {
            let record = r.downcast::<IOBluetoothSDPServiceRecord>().ok()?;
            let mut id = 0u8;
            (unsafe { record.getRFCOMMChannelID(&mut id) } == 0).then_some(id)
        })
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn address(device: &IOBluetoothDevice) -> String {
    unsafe { device.addressString() }.map(|a| a.to_string()).unwrap_or_default()
}

/// Its name, or its address while the name is not known yet (a device just found).
fn name(device: &IOBluetoothDevice) -> String {
    unsafe { device.nameOrAddress() }.map(|n| n.to_string()).unwrap_or_else(|| address(device))
}

/// AirPods and the like offer a serial channel too; a headset this reads is not an audio device
/// (the NeuroSky reports no class at all).
fn is_audio(device: &IOBluetoothDevice) -> bool {
    (unsafe { device.deviceClassMajor() }) == kBluetoothDeviceClassMajorAudio
}

/// The paired devices a headset can be, as (name, address): those with a serial channel, minus
/// audio devices.
pub fn serial_devices() -> Vec<(String, String)> {
    paired()
        .into_iter()
        .filter(|d| !channels(d).is_empty() && !is_audio(d))
        .map(|d| (name(&d), address(&d)))
        .collect()
}

/// The serial device named `name` — the name macOS gives its `/dev/cu.` entry — if one is paired.
pub fn named(name: &str) -> Option<(String, String)> {
    serial_devices().into_iter().find(|(n, _)| n == name)
}

/// Starts opening the serial channel of the paired device at `address`, its bytes to go into
/// `tx`. Returns at once; `poll` says when it opens.
pub fn open(address: &str, tx: UnboundedSender<Vec<u8>>) -> io::Result<Headset> {
    let device = paired()
        .into_iter()
        .find(|d| self::address(d) == address)
        .ok_or_else(|| io::Error::other("not paired"))?;
    let untried = channels(&device);
    let mut headset = Headset {
        device,
        untried,
        reading: None,
        tx: Some(tx),
        current: None,
        asked: Instant::now(),
        last_status: 0,
        failed: None,
    };
    if headset.untried.is_empty() {
        // Paired just now: no records stored yet. Ask for them; `poll` waits for the answer.
        unsafe { headset.device.performSDPQuery(None) };
        headset.reading = Some(Instant::now());
    } else {
        headset.attempt()?;
    }
    Ok(headset)
}

impl Headset {
    /// Asks for the next untried channel; an open that fails to start moves on to the next.
    fn attempt(&mut self) -> io::Result<()> {
        while !self.untried.is_empty() {
            let id = self.untried.remove(0);
            let Some(tx) = self.tx.clone() else { break };
            let delegate = Delegate::new(tx);
            let target: &AnyObject = &delegate;
            let mut channel = None;
            let status = unsafe {
                self.device.openRFCOMMChannelAsync_withChannelID_delegate(Some(&mut channel), id, Some(target))
            };
            if let (0, Some(channel)) = (status, channel) {
                self.current = Some((channel, delegate));
                self.asked = Instant::now();
                return Ok(());
            }
            self.last_status = status;
        }
        Err(io::Error::other(format!("no serial channel opened (IOReturn {:#x})", self.last_status as u32)))
    }

    /// Lets go of the current attempt's channel: its delegate first, so nothing calls into a
    /// delegate that is about to be released.
    fn release(&mut self) {
        if let Some((channel, _delegate)) = self.current.take() {
            unsafe {
                channel.setDelegate(None);
                channel.closeChannel();
            }
        }
    }

    /// Where the channel stands. Call after `pump`: the records, the open's result and a close
    /// arrive there.
    pub fn poll(&mut self) -> Link {
        if let Some(why) = &self.failed {
            return Link::Failed(why.clone());
        }
        if let Some(since) = self.reading {
            self.untried = channels(&self.device);
            if self.untried.is_empty() {
                return if since.elapsed() > READ_DEADLINE {
                    self.fail("it offers no serial channel".to_string())
                } else {
                    Link::Reading
                };
            }
            self.reading = None;
            return match self.attempt() {
                Ok(()) => Link::Opening,
                Err(e) => self.fail(e.to_string()),
            };
        }
        let Some((_, delegate)) = &self.current else {
            return self.fail(format!("no serial channel opened (IOReturn {:#x})", self.last_status as u32));
        };
        let seen = delegate.ivars();
        match (seen.opened.get(), seen.closed.get()) {
            // Unreachable: no channel on it will answer either.
            (None, false) if self.asked.elapsed() > OPEN_DEADLINE => {
                self.fail("not reachable — is it switched on?".to_string())
            }
            (None, false) => Link::Opening,
            (Some(0), false) => {
                self.tx = None;
                Link::Open
            }
            (Some(0), true) => Link::Closed,
            // Refused, or closed before it opened: try the next channel.
            (status, _) => {
                self.last_status = status.unwrap_or(self.last_status);
                self.release();
                match self.attempt() {
                    Ok(()) => Link::Opening,
                    Err(e) => self.fail(e.to_string()),
                }
            }
        }
    }

    /// Gives up: lets go of the attempt and keeps the reason for every later `poll`.
    fn fail(&mut self, why: String) -> Link {
        self.release();
        self.failed = Some(why.clone());
        Link::Failed(why)
    }
}

impl Drop for Headset {
    /// Closes the channel and the link, so the headset is free for the next run or another Mac.
    fn drop(&mut self) {
        self.release();
        unsafe { self.device.closeConnection() };
    }
}

// ── The search ───────────────────────────────────────────────────────────────

define_class!(
    /// The search's delegate. The devices found are read off the inquiry itself; this only
    /// records that it has finished.
    #[unsafe(super(NSObject))]
    #[name = "NKHeadsetSearch"]
    #[ivars = Cell<bool>]
    struct Searching;

    unsafe impl NSObjectProtocol for Searching {}

    unsafe impl IOBluetoothDeviceInquiryDelegate for Searching {
        #[unsafe(method(deviceInquiryComplete:error:aborted:))]
        fn complete(&self, _sender: Option<&IOBluetoothDeviceInquiry>, _error: i32, _aborted: bool) {
            self.ivars().set(true);
        }
    }
);

/// A search for nearby devices (a Bluetooth inquiry, ~10 s), started from the Headset panel.
/// Devices answer during pumps; `found` lists them as they do. Dropping it stops the search.
pub struct Search {
    inquiry: Retained<IOBluetoothDeviceInquiry>,
    _delegate: Retained<Searching>,
}

/// Starts a search. It uses the radio, so a headset already streaming may see its packets
/// delayed while it runs — which is why it runs only when the panel asks.
pub fn search() -> io::Result<Search> {
    let delegate: Retained<Searching> = {
        let this = Searching::alloc().set_ivars(Cell::new(false));
        unsafe { msg_send![super(this), init] }
    };
    let target: &AnyObject = &delegate;
    let inquiry = unsafe { IOBluetoothDeviceInquiry::inquiryWithDelegate(Some(target)) }
        .ok_or_else(|| io::Error::other("Bluetooth search unavailable"))?;
    unsafe {
        inquiry.setInquiryLength(10);
        inquiry.setUpdateNewDeviceNames(true);
    }
    match unsafe { inquiry.start() } {
        0 => Ok(Search { inquiry, _delegate: delegate }),
        status => Err(io::Error::other(format!("search did not start (IOReturn {:#x})", status as u32))),
    }
}

impl Search {
    pub fn searching(&self) -> bool {
        !self._delegate.ivars().get()
    }

    /// The devices found so far, as (name, address, paired), minus audio devices — in the order
    /// they answered. An unpaired device's services cannot be read before pairing, so this does
    /// not filter on a serial channel; a wrong choice shows as "no ThinkGear data".
    pub fn found(&self) -> Vec<(String, String, bool)> {
        let Some(devices) = (unsafe { self.inquiry.foundDevices() }) else { return Vec::new() };
        devices
            .iter()
            .filter_map(|d| d.downcast::<IOBluetoothDevice>().ok())
            .filter(|d| !is_audio(d))
            .map(|d| (name(&d), address(&d), unsafe { d.isPaired() }))
            .collect()
    }
}

impl Drop for Search {
    fn drop(&mut self) {
        unsafe {
            self.inquiry.setDelegate(None);
            self.inquiry.stop();
        }
    }
}

// ── Pairing ──────────────────────────────────────────────────────────────────

/// What the pairing's delegate has seen: a PIN asked for, a code to compare, the result.
struct Asked {
    pin: Cell<bool>,
    compare: Cell<Option<u32>>,
    finished: Cell<Option<i32>>,
}

define_class!(
    /// The pairing's delegate: the device asks for a PIN (legacy pairing, as HC-series modules
    /// do) or a code to compare (Secure Simple Pairing); the person answers in the panel.
    #[unsafe(super(NSObject))]
    #[name = "NKHeadsetPairing"]
    #[ivars = Asked]
    struct PairDelegate;

    unsafe impl NSObjectProtocol for PairDelegate {}

    unsafe impl IOBluetoothDevicePairDelegate for PairDelegate {
        #[unsafe(method(devicePairingPINCodeRequest:))]
        fn pin_request(&self, _sender: Option<&AnyObject>) {
            self.ivars().pin.set(true);
        }

        #[unsafe(method(devicePairingUserConfirmationRequest:numericValue:))]
        fn compare_request(&self, _sender: Option<&AnyObject>, value: u32) {
            self.ivars().compare.set(Some(value));
        }

        #[unsafe(method(devicePairingFinished:error:))]
        fn finished(&self, _sender: Option<&AnyObject>, error: i32) {
            self.ivars().finished.set(Some(error));
        }
    }
);

/// Where a pairing stands.
pub enum Pair {
    Pairing,
    NeedsPin,
    /// The device shows this code; the person says whether it matches.
    NeedsConfirm(u32),
    Paired,
    Failed(String),
}

/// Pairing a device the search found. Dropping it stops the pairing.
pub struct Pairing {
    pair: Retained<IOBluetoothDevicePair>,
    delegate: Retained<PairDelegate>,
    answered: bool,
}

/// Starts pairing the device at `address`.
pub fn pair(address: &str) -> io::Result<Pairing> {
    let device = unsafe { IOBluetoothDevice::deviceWithAddressString(Some(&NSString::from_str(address))) }
        .ok_or_else(|| io::Error::other("no such device"))?;
    let pair = unsafe { IOBluetoothDevicePair::pairWithDevice(Some(&device)) }
        .ok_or_else(|| io::Error::other("pairing unavailable"))?;
    let delegate: Retained<PairDelegate> = {
        let this = PairDelegate::alloc().set_ivars(Asked {
            pin: Cell::new(false),
            compare: Cell::new(None),
            finished: Cell::new(None),
        });
        unsafe { msg_send![super(this), init] }
    };
    let target: &AnyObject = &delegate;
    unsafe { pair.setDelegate(Some(target)) };
    match unsafe { pair.start() } {
        0 => Ok(Pairing { pair, delegate, answered: false }),
        status => Err(io::Error::other(format!("pairing did not start (IOReturn {:#x})", status as u32))),
    }
}

impl Pairing {
    /// Call after `pump`: the device's requests and the result arrive there.
    pub fn poll(&self) -> Pair {
        let asked = self.delegate.ivars();
        match asked.finished.get() {
            Some(0) => Pair::Paired,
            Some(status) => Pair::Failed(format!("pairing failed (IOReturn {:#x}) — wrong PIN?", status as u32)),
            None if self.answered => Pair::Pairing,
            None => match (asked.pin.get(), asked.compare.get()) {
                (true, _) => Pair::NeedsPin,
                (_, Some(code)) => Pair::NeedsConfirm(code),
                _ => Pair::Pairing,
            },
        }
    }

    /// The PIN the person typed, sent as the device asked for it.
    pub fn pin(&mut self, pin: &str) {
        let bytes = pin.as_bytes();
        let mut code = BluetoothPINCode { data: [0; 16] };
        let n = bytes.len().min(16);
        code.data[..n].copy_from_slice(&bytes[..n]);
        unsafe { self.pair.replyPINCode_PINCode(n as _, &mut code) };
        self.answered = true;
    }

    /// The person's answer to "does the device show this code?".
    pub fn confirm(&mut self, matches: bool) {
        unsafe { self.pair.replyUserConfirmation(matches) };
        self.answered = true;
    }
}

impl Drop for Pairing {
    fn drop(&mut self) {
        unsafe {
            self.pair.setDelegate(None);
            if self.delegate.ivars().finished.get().is_none() {
                self.pair.stop();
            }
        }
    }
}

// ── The run loop, and the choice kept ────────────────────────────────────────

/// Runs the main run loop's ready sources and returns — never waits. Every delegate here is
/// called during it, so this is when a search finds, a pairing asks, an open completes and the
/// channel's bytes reach the dashboard's channel.
pub fn pump() {
    while CFRunLoop::run_in_mode(unsafe { kCFRunLoopDefaultMode }, 0.0, true)
        == CFRunLoopRunResult::HandledSource
    {}
}

/// The headset chosen last — its address, beside the relay's files in `~/.config/neuralkit` — so
/// a run with no port named reconnects to it. `auth unregister` removes only its own files.
fn chosen_file() -> Option<String> {
    Some(format!("{}/.config/neuralkit/headset", std::env::var("HOME").ok()?))
}

pub fn remember(address: &str) {
    if let Some(path) = chosen_file() {
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, format!("{address}\n"));
    }
}

/// The remembered headset as (name, address), if it is still a paired serial device.
pub fn remembered() -> Option<(String, String)> {
    let address = std::fs::read_to_string(chosen_file()?).ok()?.trim().to_string();
    serial_devices().into_iter().find(|(_, a)| *a == address)
}
