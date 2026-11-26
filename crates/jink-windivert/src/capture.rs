//! The WinDivert capture loop (Windows only).
//!
//! For each captured packet: run it through the engine, send the forged and
//! replayed packets on the interface it came from, then reinject the original
//! if the verdict is [`Verdict::Pass`]. When the loop ends (asked to with
//! [`Stop`], or the process ends), the WinDivert handle closes and traffic
//! flows normally again.

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use jink_core::desync::{PlanError, Verdict};
use jink_core::engine::{Direction, PacketEngine};
use windivert::WinDivert;
use windivert::address::WinDivertAddress;
use windivert::error::{WinDivertError, WinDivertOpenError, WinDivertRecvError};
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::prelude::WinDivertFlags;

/// How long one wait for a packet lasts: how quickly the loop notices
/// [`Stop`], and how often held packets are checked for expiry when the
/// network is quiet.
const WAIT_MS: u32 = 100;
/// How often held packets are checked for expiry.
const EXPIRY_CHECK: Duration = Duration::from_millis(100);
/// Largest IP packet WinDivert can deliver.
const BUFFER_LEN: usize = 65_535;

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("WinDivert64.sys was not found next to the executable")]
    MissingDriver,
    #[error("access denied: run jink as Administrator")]
    AccessDenied,
    #[error("the WinDivert driver could not be loaded: {0}")]
    Open(WinDivertError),
    #[error("receiving a packet failed: {0}")]
    Recv(WinDivertError),
}

/// Something worth knowing while running.
#[derive(Debug)]
pub enum Event {
    /// WinDivert is open: traffic goes through jink from now on.
    Capturing,
    /// A rule could not be applied; the packet went out unchanged.
    PlanFailed(PlanError),
    /// WinDivert refused to send a packet.
    SendFailed(String),
}

/// Asks a running [`run`] to end; clones share the request.
#[derive(Debug, Clone, Default)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `run` ends within [`WAIT_MS`] (after the packet in hand, if any).
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn asked(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Captures with `filter` and processes packets until `stop` asks it to end
/// (then `Ok`) or an error occurs.
///
/// # Errors
/// [`RunError`] if WinDivert cannot be opened or receiving fails.
pub fn run(
    engine: &mut PacketEngine,
    filter: &str,
    on_event: &mut dyn FnMut(Event),
    stop: &Stop,
) -> Result<(), RunError> {
    let divert = WinDivert::network(filter, 0, WinDivertFlags::new()).map_err(|e| match e {
        WinDivertError::Open(WinDivertOpenError::MissingSYS) => RunError::MissingDriver,
        WinDivertError::Open(WinDivertOpenError::AccessDenied) => RunError::AccessDenied,
        other => RunError::Open(other),
    })?;
    on_event(Event::Capturing);
    let mut buffer = vec![0_u8; BUFFER_LEN];
    // The latest outbound address: a template for sending released packets.
    let mut template: Option<WinDivertAddress<NetworkLayer>> = None;
    let mut last_expiry = Instant::now();
    while !stop.asked() {
        match divert.recv_wait(&mut buffer, WAIT_MS) {
            Ok(Some(packet)) => {
                if let Some(outbound) = process(&divert, engine, &packet, on_event) {
                    template = Some(outbound);
                }
            }
            // Nothing within the wait.
            Ok(None) | Err(WinDivertError::Recv(WinDivertRecvError::InsufficientBuffer)) => {}
            Err(e) => return Err(RunError::Recv(e)),
        }
        let now = Instant::now();
        if now.saturating_duration_since(last_expiry) >= EXPIRY_CHECK {
            last_expiry = now;
            release(&divert, engine, template.as_ref(), now, on_event);
        }
    }
    Ok(())
}

/// Runs one captured packet through the engine; its address if outbound.
fn process(
    divert: &WinDivert<NetworkLayer>,
    engine: &mut PacketEngine,
    packet: &WinDivertPacket<'_, NetworkLayer>,
    on_event: &mut dyn FnMut(Event),
) -> Option<WinDivertAddress<NetworkLayer>> {
    let address = &packet.address;
    let direction = if address.outbound() {
        Direction::Outbound
    } else {
        Direction::Inbound
    };
    let out = engine.process(
        &packet.data,
        direction,
        interface_tag(address),
        Instant::now(),
    );
    out.errors
        .into_iter()
        .for_each(|e| on_event(Event::PlanFailed(e)));
    for bytes in out.send {
        send(divert, forged_address(address), bytes, on_event);
    }
    if out.original == Verdict::Pass
        && let Err(e) = divert.send(packet)
    {
        on_event(Event::SendFailed(e.to_string()));
    }
    address.outbound().then(|| address.clone())
}

/// Sends the held packets whose time is up.
fn release(
    divert: &WinDivert<NetworkLayer>,
    engine: &mut PacketEngine,
    template: Option<&WinDivertAddress<NetworkLayer>>,
    now: Instant,
    on_event: &mut dyn FnMut(Event),
) {
    let released = engine.expire_holds(now);
    released
        .errors
        .into_iter()
        .for_each(|e| on_event(Event::PlanFailed(e)));
    if let Some(template) = template {
        for p in released.packets {
            let mut address = forged_address(template);
            set_interface(&mut address, p.tag);
            send(divert, address, p.bytes, on_event);
        }
    }
}

fn send(
    divert: &WinDivert<NetworkLayer>,
    address: WinDivertAddress<NetworkLayer>,
    bytes: Vec<u8>,
    on_event: &mut dyn FnMut(Event),
) {
    let packet = WinDivertPacket {
        address,
        data: Cow::Owned(bytes),
    };
    if let Err(e) = divert.send(&packet) {
        on_event(Event::SendFailed(e.to_string()));
    }
}

/// An outbound address on the same interface, with every checksum marked
/// valid (jink computes them), as zapret does for its own packets.
fn forged_address(from: &WinDivertAddress<NetworkLayer>) -> WinDivertAddress<NetworkLayer> {
    let mut address = from.clone();
    address.set_outbound(true);
    address.set_impostor(false);
    address.set_ip_checksum(true);
    address.set_tcp_checksum(true);
    address.set_udp_checksum(true);
    address
}

/// Interface and sub-interface index packed into the engine's opaque tag.
fn interface_tag(address: &WinDivertAddress<NetworkLayer>) -> u64 {
    u64::from(address.interface_index()).wrapping_shl(32) | u64::from(address.subinterface_index())
}

fn set_interface(address: &mut WinDivertAddress<NetworkLayer>, tag: u64) {
    address.set_interface_index(u32::try_from(tag.wrapping_shr(32)).unwrap_or(0));
    address.set_subinterface_index(u32::try_from(tag & 0xffff_ffff).unwrap_or(0));
}
