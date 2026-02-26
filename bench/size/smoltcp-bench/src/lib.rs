//! smoltcp binary size benchmark scenarios.
//!
//! Each scenario is behind a feature gate and exports a single `extern "C"` fn.
//! Build one scenario at a time: `cargo build --release --features scenario-X`

#![no_std]

// -- Panic handler for freestanding targets ----------------------------------

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

// -- Scenario A: Minimal TCP/IPv4 --------------------------------------------

#[cfg(feature = "scenario-a")]
mod scenario_a {
    use super::device::BenchDevice;
    use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_a() -> bool {
        let mut device = BenchDevice;
        let config =
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
                .unwrap();
        });

        static mut TCP_RX: [u8; 4096] = [0; 4096];
        static mut TCP_TX: [u8; 4096] = [0; 4096];
        let rx = tcp::SocketBuffer::new(unsafe { &mut TCP_RX[..] });
        let tx = tcp::SocketBuffer::new(unsafe { &mut TCP_TX[..] });
        let socket = tcp::Socket::new(rx, tx);

        let mut storage = [SocketStorage::EMPTY; 1];
        let mut sockets = SocketSet::new(&mut storage[..]);
        let _handle = sockets.add(socket);

        let result = iface.poll(Instant::from_millis(0), &mut device, &mut sockets);
        core::hint::black_box(result);
        true
    }
}

// -- Scenario B: TCP + UDP + ICMP / IPv4 -------------------------------------

#[cfg(feature = "scenario-b")]
mod scenario_b {
    use super::device::BenchDevice;
    use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
    use smoltcp::socket::{icmp, tcp, udp};
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_b() -> bool {
        let mut device = BenchDevice;
        let config =
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
                .unwrap();
        });

        // TCP
        static mut TCP_RX: [u8; 4096] = [0; 4096];
        static mut TCP_TX: [u8; 4096] = [0; 4096];
        let tcp_rx = tcp::SocketBuffer::new(unsafe { &mut TCP_RX[..] });
        let tcp_tx = tcp::SocketBuffer::new(unsafe { &mut TCP_TX[..] });
        let tcp_socket = tcp::Socket::new(tcp_rx, tcp_tx);

        // UDP
        static mut UDP_RX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP_RX_DATA: [u8; 512] = [0; 512];
        static mut UDP_TX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP_TX_DATA: [u8; 512] = [0; 512];
        let udp_rx = udp::PacketBuffer::new(
            unsafe { &mut UDP_RX_META[..] },
            unsafe { &mut UDP_RX_DATA[..] },
        );
        let udp_tx = udp::PacketBuffer::new(
            unsafe { &mut UDP_TX_META[..] },
            unsafe { &mut UDP_TX_DATA[..] },
        );
        let udp_socket = udp::Socket::new(udp_rx, udp_tx);

        // ICMP
        static mut ICMP_RX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP_RX_DATA: [u8; 512] = [0; 512];
        static mut ICMP_TX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP_TX_DATA: [u8; 512] = [0; 512];
        let icmp_rx = icmp::PacketBuffer::new(
            unsafe { &mut ICMP_RX_META[..] },
            unsafe { &mut ICMP_RX_DATA[..] },
        );
        let icmp_tx = icmp::PacketBuffer::new(
            unsafe { &mut ICMP_TX_META[..] },
            unsafe { &mut ICMP_TX_DATA[..] },
        );
        let icmp_socket = icmp::Socket::new(icmp_rx, icmp_tx);

        let mut storage = [SocketStorage::EMPTY; 3];
        let mut sockets = SocketSet::new(&mut storage[..]);
        let _h1 = sockets.add(tcp_socket);
        let _h2 = sockets.add(udp_socket);
        let _h3 = sockets.add(icmp_socket);

        let result = iface.poll(Instant::from_millis(0), &mut device, &mut sockets);
        core::hint::black_box(result);
        true
    }
}

// -- Scenario C: Full IPv4 ---------------------------------------------------

#[cfg(feature = "scenario-c")]
mod scenario_c {
    use super::device::BenchDevice;
    use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
    use smoltcp::socket::{dhcpv4, dns, icmp, raw, tcp, udp};
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpProtocol};

    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_c() -> bool {
        let mut device = BenchDevice;
        let config =
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
                .unwrap();
        });

        // TCP
        static mut TCP_RX: [u8; 4096] = [0; 4096];
        static mut TCP_TX: [u8; 4096] = [0; 4096];
        let tcp_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(unsafe { &mut TCP_RX[..] }),
            tcp::SocketBuffer::new(unsafe { &mut TCP_TX[..] }),
        );

        // UDP
        static mut UDP_RX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP_RX_DATA: [u8; 512] = [0; 512];
        static mut UDP_TX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP_TX_DATA: [u8; 512] = [0; 512];
        let udp_socket = udp::Socket::new(
            udp::PacketBuffer::new(
                unsafe { &mut UDP_RX_META[..] },
                unsafe { &mut UDP_RX_DATA[..] },
            ),
            udp::PacketBuffer::new(
                unsafe { &mut UDP_TX_META[..] },
                unsafe { &mut UDP_TX_DATA[..] },
            ),
        );

        // ICMP
        static mut ICMP_RX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP_RX_DATA: [u8; 512] = [0; 512];
        static mut ICMP_TX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP_TX_DATA: [u8; 512] = [0; 512];
        let icmp_socket = icmp::Socket::new(
            icmp::PacketBuffer::new(
                unsafe { &mut ICMP_RX_META[..] },
                unsafe { &mut ICMP_RX_DATA[..] },
            ),
            icmp::PacketBuffer::new(
                unsafe { &mut ICMP_TX_META[..] },
                unsafe { &mut ICMP_TX_DATA[..] },
            ),
        );

        // DHCP
        let dhcp_socket = dhcpv4::Socket::new();

        // DNS
        static mut DNS_QUERIES: [Option<dns::DnsQuery>; 1] = [None; 1];
        let dns_socket = dns::Socket::new(
            &[IpAddress::v4(8, 8, 8, 8)],
            unsafe { &mut DNS_QUERIES[..] },
        );

        // Raw
        static mut RAW_RX_META: [raw::PacketMetadata; 4] =
            [raw::PacketMetadata::EMPTY; 4];
        static mut RAW_RX_DATA: [u8; 512] = [0; 512];
        static mut RAW_TX_META: [raw::PacketMetadata; 4] =
            [raw::PacketMetadata::EMPTY; 4];
        static mut RAW_TX_DATA: [u8; 512] = [0; 512];
        let raw_socket = raw::Socket::new(
            Some(smoltcp::wire::IpVersion::Ipv4),
            Some(IpProtocol::Unknown(253)),
            raw::PacketBuffer::new(
                unsafe { &mut RAW_RX_META[..] },
                unsafe { &mut RAW_RX_DATA[..] },
            ),
            raw::PacketBuffer::new(
                unsafe { &mut RAW_TX_META[..] },
                unsafe { &mut RAW_TX_DATA[..] },
            ),
        );

        let mut storage = [SocketStorage::EMPTY; 6];
        let mut sockets = SocketSet::new(&mut storage[..]);
        let _h1 = sockets.add(tcp_socket);
        let _h2 = sockets.add(udp_socket);
        let _h3 = sockets.add(icmp_socket);
        let _h4 = sockets.add(dhcp_socket);
        let _h5 = sockets.add(dns_socket);
        let _h6 = sockets.add(raw_socket);

        let result = iface.poll(Instant::from_millis(0), &mut device, &mut sockets);
        core::hint::black_box(result);
        true
    }
}

// -- Scenario D: Dual-stack IPv4 + IPv6 --------------------------------------

#[cfg(feature = "scenario-d")]
mod scenario_d {
    use super::device::BenchDevice;
    use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
    use smoltcp::socket::{icmp, tcp, udp};
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

    #[unsafe(no_mangle)]
    pub extern "C" fn bench_scenario_d() -> bool {
        let mut device = BenchDevice;
        let config =
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24))
                .unwrap();
            addrs
                .push(IpCidr::new(
                    IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1),
                    64,
                ))
                .unwrap();
        });

        // TCP v4
        static mut TCP4_RX: [u8; 4096] = [0; 4096];
        static mut TCP4_TX: [u8; 4096] = [0; 4096];
        let tcp4 = tcp::Socket::new(
            tcp::SocketBuffer::new(unsafe { &mut TCP4_RX[..] }),
            tcp::SocketBuffer::new(unsafe { &mut TCP4_TX[..] }),
        );

        // TCP v6
        static mut TCP6_RX: [u8; 4096] = [0; 4096];
        static mut TCP6_TX: [u8; 4096] = [0; 4096];
        let tcp6 = tcp::Socket::new(
            tcp::SocketBuffer::new(unsafe { &mut TCP6_RX[..] }),
            tcp::SocketBuffer::new(unsafe { &mut TCP6_TX[..] }),
        );

        // UDP v4
        static mut UDP4_RX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP4_RX_DATA: [u8; 512] = [0; 512];
        static mut UDP4_TX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP4_TX_DATA: [u8; 512] = [0; 512];
        let udp4 = udp::Socket::new(
            udp::PacketBuffer::new(
                unsafe { &mut UDP4_RX_META[..] },
                unsafe { &mut UDP4_RX_DATA[..] },
            ),
            udp::PacketBuffer::new(
                unsafe { &mut UDP4_TX_META[..] },
                unsafe { &mut UDP4_TX_DATA[..] },
            ),
        );

        // UDP v6
        static mut UDP6_RX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP6_RX_DATA: [u8; 512] = [0; 512];
        static mut UDP6_TX_META: [udp::PacketMetadata; 4] =
            [udp::PacketMetadata::EMPTY; 4];
        static mut UDP6_TX_DATA: [u8; 512] = [0; 512];
        let udp6 = udp::Socket::new(
            udp::PacketBuffer::new(
                unsafe { &mut UDP6_RX_META[..] },
                unsafe { &mut UDP6_RX_DATA[..] },
            ),
            udp::PacketBuffer::new(
                unsafe { &mut UDP6_TX_META[..] },
                unsafe { &mut UDP6_TX_DATA[..] },
            ),
        );

        // ICMP v4
        static mut ICMP4_RX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP4_RX_DATA: [u8; 512] = [0; 512];
        static mut ICMP4_TX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP4_TX_DATA: [u8; 512] = [0; 512];
        let icmp4 = icmp::Socket::new(
            icmp::PacketBuffer::new(
                unsafe { &mut ICMP4_RX_META[..] },
                unsafe { &mut ICMP4_RX_DATA[..] },
            ),
            icmp::PacketBuffer::new(
                unsafe { &mut ICMP4_TX_META[..] },
                unsafe { &mut ICMP4_TX_DATA[..] },
            ),
        );

        // ICMP v6
        static mut ICMP6_RX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP6_RX_DATA: [u8; 512] = [0; 512];
        static mut ICMP6_TX_META: [icmp::PacketMetadata; 4] =
            [icmp::PacketMetadata::EMPTY; 4];
        static mut ICMP6_TX_DATA: [u8; 512] = [0; 512];
        let icmp6 = icmp::Socket::new(
            icmp::PacketBuffer::new(
                unsafe { &mut ICMP6_RX_META[..] },
                unsafe { &mut ICMP6_RX_DATA[..] },
            ),
            icmp::PacketBuffer::new(
                unsafe { &mut ICMP6_TX_META[..] },
                unsafe { &mut ICMP6_TX_DATA[..] },
            ),
        );

        let mut storage = [SocketStorage::EMPTY; 6];
        let mut sockets = SocketSet::new(&mut storage[..]);
        let _h1 = sockets.add(tcp4);
        let _h2 = sockets.add(tcp6);
        let _h3 = sockets.add(udp4);
        let _h4 = sockets.add(udp6);
        let _h5 = sockets.add(icmp4);
        let _h6 = sockets.add(icmp6);

        let result = iface.poll(Instant::from_millis(0), &mut device, &mut sockets);
        core::hint::black_box(result);
        true
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

        // Parse Ethernet
        let Ok(eth_frame) = EthernetFrame::new_checked(frame) else {
            return 0;
        };
        let Ok(eth_repr) = EthernetRepr::parse(&eth_frame) else {
            return 0;
        };
        result = result.wrapping_add(u16::from(eth_repr.ethertype) as u32);

        // Parse IPv4
        let payload = eth_frame.payload();
        let Ok(ipv4_pkt) = Ipv4Packet::new_checked(payload) else {
            return result;
        };
        let Ok(ipv4_repr) = Ipv4Repr::parse(&ipv4_pkt, &caps) else {
            return result;
        };
        result = result.wrapping_add(ipv4_repr.payload_len as u32);

        // Parse TCP
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

        // Parse UDP
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

        // Parse IPv6 (pull in v6 wire code)
        if let Ok(ipv6_pkt) = Ipv6Packet::new_checked(payload) {
            if let Ok(ipv6_repr) = Ipv6Repr::parse(&ipv6_pkt) {
                result = result.wrapping_add(ipv6_repr.payload_len as u32);
            }
        }

        // Emit IPv4
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
