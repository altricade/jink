//! Resolving split markers to byte offsets (zapret `ResolvePos`,
//! `ResolveMultiPos`, `pos_normalize` in `nfq/protocol.c` and `desync.c`).

use std::ops::Range;

use crate::config::{Marker, MarkerBase};
use crate::l7::host::HostName;
use crate::l7::http::HttpRequest;
use crate::l7::tls::ClientHello;

/// Protocol positions known in a message (offsets from its first byte).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Positions {
    /// HTTP method start.
    pub method: Option<usize>,
    pub host: Option<Range<usize>>,
    pub sld: Option<Range<usize>>,
    pub mid_sld: Option<usize>,
    /// Start of the TLS SNI extension's data.
    pub sni_ext: Option<usize>,
}

impl Positions {
    #[must_use]
    pub fn from_tls(hello: &ClientHello<'_>) -> Self {
        hello
            .server_name
            .as_ref()
            .map_or_else(Self::default, |sni| Self {
                sni_ext: Some(sni.ext_data_offset),
                ..Self::from_host(&sni.host)
            })
    }

    #[must_use]
    pub fn from_http(request: &HttpRequest<'_>) -> Self {
        Self {
            method: Some(0),
            ..request
                .host
                .as_ref()
                .map_or_else(Self::default, Self::from_host)
        }
    }

    fn from_host(host: &HostName<'_>) -> Self {
        Self {
            method: None,
            host: Some(host.range.clone()),
            sld: host.sld_range.clone(),
            mid_sld: host.mid_sld(),
            sni_ext: None,
        }
    }
}

/// zapret `ResolvePos` + `CheckPos`: the offset a marker points to in a
/// message of `len` bytes, or `None` if the base is unknown or the result
/// falls outside `1..len` (position 0 means "no split" in zapret).
#[must_use]
pub fn resolve(marker: Marker, positions: &Positions, len: usize) -> Option<usize> {
    let offset = isize::from(marker.offset);
    let base = match marker.base {
        MarkerBase::Absolute if offset < 0 => len,
        MarkerBase::Absolute => 0,
        MarkerBase::Method => positions.method?,
        MarkerBase::Host => positions.host.as_ref()?.start,
        MarkerBase::EndHost => positions.host.as_ref()?.end,
        MarkerBase::Sld => positions.sld.as_ref()?.start,
        MarkerBase::EndSld => positions.sld.as_ref()?.end,
        MarkerBase::MidSld => positions.mid_sld?,
        MarkerBase::SniExt => positions.sni_ext?,
    };
    base.checked_add_signed(offset)
        .filter(|&p| p > 0 && p < len)
}

/// Split points inside one packet of a message (zapret `ResolveMultiPos` +
/// `pos_normalize`): markers are resolved against the whole message received
/// so far (`message_len` bytes), then kept only if they fall strictly inside
/// the packet that starts at `packet_offset` with `packet_len` bytes, and
/// returned relative to that packet, sorted and without duplicates.
#[must_use]
pub fn split_points(
    markers: &[Marker],
    positions: &Positions,
    message_len: usize,
    packet_offset: usize,
    packet_len: usize,
) -> Vec<usize> {
    let mut points: Vec<usize> = markers
        .iter()
        .filter_map(|&m| resolve(m, positions, message_len))
        .filter_map(|p| p.checked_sub(packet_offset))
        .filter(|&p| p > 0 && p < packet_len)
        .collect();
    points.sort_unstable();
    points.dedup();
    points
}

#[cfg(test)]
mod tests {
    use super::{Positions, resolve, split_points};
    use crate::config::{Marker, MarkerBase};

    const fn m(base: MarkerBase, offset: i16) -> Marker {
        Marker { base, offset }
    }

    fn google_like() -> Positions {
        // www.google.com at 125..139, sld google at 129..135, SNI ext at 120.
        Positions {
            method: None,
            host: Some(125..139),
            sld: Some(129..135),
            mid_sld: Some(132),
            sni_ext: Some(120),
        }
    }

    #[test]
    fn markers_resolve_like_zapret() {
        let p = google_like();
        assert_eq!(resolve(m(MarkerBase::Absolute, 1), &p, 681), Some(1));
        assert_eq!(resolve(m(MarkerBase::Absolute, -10), &p, 681), Some(671));
        assert_eq!(resolve(m(MarkerBase::SniExt, 1), &p, 681), Some(121));
        assert_eq!(resolve(m(MarkerBase::MidSld, 0), &p, 681), Some(132));
        assert_eq!(resolve(m(MarkerBase::EndHost, -2), &p, 681), Some(137));
        // Out of range or unknown base: no split.
        assert_eq!(resolve(m(MarkerBase::Absolute, 700), &p, 681), None);
        assert_eq!(resolve(m(MarkerBase::Absolute, -700), &p, 681), None);
        assert_eq!(resolve(m(MarkerBase::Method, 2), &p, 681), None);
        assert_eq!(
            resolve(m(MarkerBase::Host, 0), &Positions::default(), 681),
            None
        );
    }

    #[test]
    fn split_points_are_per_packet() {
        let p = google_like();
        let markers = [
            m(MarkerBase::Absolute, 2),
            m(MarkerBase::SniExt, 1),
            m(MarkerBase::Absolute, 2),
        ];
        // Whole message in one packet: sorted, deduplicated.
        assert_eq!(split_points(&markers, &p, 681, 0, 681), vec![2, 121]);
        // First 100 bytes: only position 2 falls inside.
        assert_eq!(split_points(&markers, &p, 681, 0, 100), vec![2]);
        // Packet at offset 100: sniext+1 = 121 becomes 21 inside it.
        assert_eq!(split_points(&markers, &p, 681, 100, 581), vec![21]);
        // A point exactly at a packet boundary splits nothing.
        assert_eq!(
            split_points(&[m(MarkerBase::Absolute, 100)], &p, 681, 100, 581),
            Vec::<usize>::new()
        );
    }
}
