//! smoltcp binary size benchmark scenarios.
//!
//! Each scenario is behind a feature gate and exports a single `extern "C"` fn.
//! Build one scenario at a time: `cargo build --release --features scenario-X`

#![no_std]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// -- BenchDevice (shared across socket scenarios) ----------------------------

#[cfg(any(
    feature = "scenario-a",
    feature = "scenario-b",
    feature = "scenario-c",
    feature = "scenario-d",
))]
mod device {
    use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
    use smoltcp::time::Instant;

    pub struct BenchDevice;

    pub struct BenchRxToken;
    pub struct BenchTxToken;

    impl phy::RxToken for BenchRxToken {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            static BUF: [u8; 0] = [];
            f(&BUF)
        }
    }

    impl phy::TxToken for BenchTxToken {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            static mut BUF: [u8; 1536] = [0; 1536];
            f(unsafe { &mut BUF[..len] })
        }
    }

    impl Device for BenchDevice {
        type RxToken<'a> = BenchRxToken;
        type TxToken<'a> = BenchTxToken;

        fn receive(
            &mut self,
            _timestamp: Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            None
        }

        fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
            Some(BenchTxToken)
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ethernet;
            caps.max_transmission_unit = 1514;
            caps
        }
    }
}

// -- Helpers for socket scenarios --------------------------------------------

macro_rules! bench_iface {
    () => {{
        use super::device::BenchDevice;
        use smoltcp::iface::{Config, Interface};
        use smoltcp::time::Instant;
        use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

        let mut device = BenchDevice;
        let config =
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
                .unwrap();
        });
        (device, iface)
    }};
}

macro_rules! tcp_socket {
    ($storage:ident, $name:ident) => {
        static mut $storage: ([u8; 4096], [u8; 4096]) = ([0; 4096], [0; 4096]);
        let $name = unsafe {
            smoltcp::socket::tcp::Socket::new(
                smoltcp::socket::tcp::SocketBuffer::new(&mut $storage.0[..]),
                smoltcp::socket::tcp::SocketBuffer::new(&mut $storage.1[..]),
            )
        };
    };
}

macro_rules! udp_socket {
    ($storage:ident, $name:ident) => {
        static mut $storage: (
            [smoltcp::socket::udp::PacketMetadata; 4],
            [u8; 512],
            [smoltcp::socket::udp::PacketMetadata; 4],
            [u8; 512],
        ) = (
            [smoltcp::socket::udp::PacketMetadata::EMPTY; 4],
            [0; 512],
            [smoltcp::socket::udp::PacketMetadata::EMPTY; 4],
            [0; 512],
        );
        let $name = unsafe {
            smoltcp::socket::udp::Socket::new(
                smoltcp::socket::udp::PacketBuffer::new(&mut $storage.0[..], &mut $storage.1[..]),
                smoltcp::socket::udp::PacketBuffer::new(&mut $storage.2[..], &mut $storage.3[..]),
            )
        };
    };
}

macro_rules! icmp_socket {
    ($storage:ident, $name:ident) => {
        static mut $storage: (
            [smoltcp::socket::icmp::PacketMetadata; 4],
            [u8; 512],
            [smoltcp::socket::icmp::PacketMetadata; 4],
            [u8; 512],
        ) = (
            [smoltcp::socket::icmp::PacketMetadata::EMPTY; 4],
            [0; 512],
            [smoltcp::socket::icmp::PacketMetadata::EMPTY; 4],
            [0; 512],
        );
        let $name = unsafe {
            smoltcp::socket::icmp::Socket::new(
                smoltcp::socket::icmp::PacketBuffer::new(&mut $storage.0[..], &mut $storage.1[..]),
                smoltcp::socket::icmp::PacketBuffer::new(&mut $storage.2[..], &mut $storage.3[..]),
            )
        };
    };
}

macro_rules! bench_poll {
    ($iface:expr, $device:expr, $n:expr, [$($sock:expr),+ $(,)?]) => {{
        use smoltcp::iface::{SocketSet, SocketStorage};
        use smoltcp::time::Instant;

        let mut storage = [SocketStorage::EMPTY; $n];
        let mut sockets = SocketSet::new(&mut storage[..]);
        $( let _ = sockets.add($sock); )+
        let result = $iface.poll(Instant::from_millis(0), $device, &mut sockets);
        core::hint::black_box(result);
        true
    }};
}

// -- Scenario A: Minimal TCP/IPv4 --------------------------------------------

#[cfg(feature = "scenario-a")]
mod scenario_a {
    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_a() -> bool {
        let (mut device, mut iface) = bench_iface!();
        tcp_socket!(TCP_BUF, tcp);
        bench_poll!(iface, &mut device, 1, [tcp])
    }
}

// -- Scenario B: TCP + UDP + ICMP / IPv4 -------------------------------------

#[cfg(feature = "scenario-b")]
mod scenario_b {
    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_b() -> bool {
        let (mut device, mut iface) = bench_iface!();
        tcp_socket!(TCP_BUF, tcp);
        udp_socket!(UDP_BUF, udp);
        icmp_socket!(ICMP_BUF, icmp);
        bench_poll!(iface, &mut device, 3, [tcp, udp, icmp])
    }
}

// -- Scenario C: Full IPv4 ---------------------------------------------------

#[cfg(feature = "scenario-c")]
mod scenario_c {
    use smoltcp::socket::{dhcpv4, dns, raw};
    use smoltcp::wire::{IpAddress, IpProtocol};

    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_c() -> bool {
        let (mut device, mut iface) = bench_iface!();

        tcp_socket!(TCP_BUF, tcp);
        udp_socket!(UDP_BUF, udp);
        icmp_socket!(ICMP_BUF, icmp);

        let dhcp_socket = dhcpv4::Socket::new();

        static mut DNS_QUERIES: [Option<dns::DnsQuery>; 1] = [None; 1];
        let dns_socket = dns::Socket::new(
            &[IpAddress::v4(8, 8, 8, 8)],
            unsafe { &mut DNS_QUERIES[..] },
        );

        static mut RAW_BUFS: (
            [raw::PacketMetadata; 4],
            [u8; 512],
            [raw::PacketMetadata; 4],
            [u8; 512],
        ) = (
            [raw::PacketMetadata::EMPTY; 4],
            [0; 512],
            [raw::PacketMetadata::EMPTY; 4],
            [0; 512],
        );
        let raw_socket = raw::Socket::new(
            Some(smoltcp::wire::IpVersion::Ipv4),
            Some(IpProtocol::Unknown(253)),
            raw::PacketBuffer::new(
                unsafe { &mut RAW_BUFS.0[..] },
                unsafe { &mut RAW_BUFS.1[..] },
            ),
            raw::PacketBuffer::new(
                unsafe { &mut RAW_BUFS.2[..] },
                unsafe { &mut RAW_BUFS.3[..] },
            ),
        );

        bench_poll!(iface, &mut device, 6, [
            tcp, udp, icmp, dhcp_socket, dns_socket, raw_socket
        ])
    }
}

// -- Scenario D: Dual-stack IPv4 + IPv6 --------------------------------------

#[cfg(feature = "scenario-d")]
mod scenario_d {
    use smoltcp::wire::{IpAddress, IpCidr};

    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_d() -> bool {
        let (mut device, mut iface) = bench_iface!();
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(
                    IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1),
                    64,
                ))
                .unwrap();
        });

        tcp_socket!(TCP4_BUF, tcp4);
        tcp_socket!(TCP6_BUF, tcp6);
        udp_socket!(UDP4_BUF, udp4);
        udp_socket!(UDP6_BUF, udp6);
        icmp_socket!(ICMP4_BUF, icmp4);
        icmp_socket!(ICMP6_BUF, icmp6);

        bench_poll!(iface, &mut device, 6, [tcp4, tcp6, udp4, udp6, icmp4, icmp6])
    }
}

// -- Scenario E: Wire-only (parse/emit, no sockets) --------------------------

#[cfg(feature = "scenario-e")]
mod scenario_e {
    use smoltcp::wire::{
        EthernetFrame, EthernetRepr, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
        TcpPacket, TcpRepr, UdpPacket, UdpRepr,
    };

    use smoltcp::phy::ChecksumCapabilities;

    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_e(input: *const u8, input_len: usize) -> u32 {
        let frame = unsafe { core::slice::from_raw_parts(input, input_len) };
        let caps = ChecksumCapabilities::default();
        let mut result: u32 = 0;

        let Ok(eth_frame) = EthernetFrame::new_checked(frame) else {
            return 0;
        };
        let Ok(eth_repr) = EthernetRepr::parse(&eth_frame) else {
            return 0;
        };
        result = result.wrapping_add(u16::from(eth_repr.ethertype) as u32);

        let payload = eth_frame.payload();
        let Ok(ipv4_pkt) = Ipv4Packet::new_checked(payload) else {
            return result;
        };
        let Ok(ipv4_repr) = Ipv4Repr::parse(&ipv4_pkt, &caps) else {
            return result;
        };
        result = result.wrapping_add(ipv4_repr.payload_len as u32);

        let tcp_payload = ipv4_pkt.payload();
        if let Ok(tcp_pkt) = TcpPacket::new_checked(tcp_payload) {
            if let Ok(tcp_repr) = TcpRepr::parse(
                &tcp_pkt,
                &ipv4_repr.src_addr.into(),
                &ipv4_repr.dst_addr.into(),
                &caps,
            ) {
                result = result
                    .wrapping_add(tcp_repr.src_port as u32)
                    .wrapping_add(tcp_repr.dst_port as u32);
            }
        }

        if let Ok(udp_pkt) = UdpPacket::new_checked(tcp_payload) {
            if let Ok(udp_repr) = UdpRepr::parse(
                &udp_pkt,
                &ipv4_repr.src_addr.into(),
                &ipv4_repr.dst_addr.into(),
                &caps,
            ) {
                result = result
                    .wrapping_add(udp_repr.src_port as u32)
                    .wrapping_add(udp_repr.dst_port as u32);
            }
        }

        if let Ok(ipv6_pkt) = Ipv6Packet::new_checked(payload) {
            if let Ok(ipv6_repr) = Ipv6Repr::parse(&ipv6_pkt) {
                result = result.wrapping_add(ipv6_repr.payload_len as u32);
            }
        }

        static mut EMIT_BUF: [u8; 1514] = [0; 1514];
        let emit_buf = unsafe { &mut EMIT_BUF[..] };

        let ipv4_emit = Ipv4Repr {
            src_addr: smoltcp::wire::Ipv4Address::new(10, 0, 0, 1),
            dst_addr: smoltcp::wire::Ipv4Address::new(10, 0, 0, 2),
            next_header: smoltcp::wire::IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        };
        if let Ok(mut pkt) = Ipv4Packet::new_checked(&mut emit_buf[14..]) {
            ipv4_emit.emit(&mut pkt, &caps);
        }

        core::hint::black_box(result)
    }
}
