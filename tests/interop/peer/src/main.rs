//! smoltcp peer for the zmoltcp interop harness.
//!
//! Wire protocol on stdin/stdout, every message `[type: u8][len: u32 LE][payload]`.
//! The harness sends one request at a time and reads until it sees the `A` reply, so
//! the exchange is fully synchronous and deterministic. Time never comes from the wall
//! clock: `T` carries the virtual time in microseconds.
//!
//! Requests: H hello/config, T time+poll, F frame in, L listen, K connect, S send stream,
//! E echo, R recv enable, M recv limit, V recv n bytes now, X close, Z abort, Q query, B bye.
//! Replies: F frames out (only before the A of a T), A ack with payload.

#[cfg(feature = "master")]
extern crate smoltcp_master as smoltcp;
#[cfg(feature = "ref")]
extern crate smoltcp_ref as smoltcp;

use std::collections::VecDeque;
use std::io::{self, BufWriter, Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv6Address};

const PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const HARNESS_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const PEER_V4: [u8; 4] = [10, 0, 0, 2];
const HARNESS_V4: [u8; 4] = [10, 0, 0, 1];

static TS_CLOCK_MS: AtomicU32 = AtomicU32::new(0);

fn tsval() -> u32 {
    TS_CLOCK_MS.load(Ordering::Relaxed)
}

fn eui64_link_local(mac: [u8; 6]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8] = mac[0] ^ 0x02;
    a[9] = mac[1];
    a[10] = mac[2];
    a[11] = 0xff;
    a[12] = 0xfe;
    a[13] = mac[3];
    a[14] = mac[4];
    a[15] = mac[5];
    a
}

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

struct LinkDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

struct LinkRx(Vec<u8>);
struct LinkTx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for LinkRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<'a> TxToken for LinkTx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for LinkDevice {
    type RxToken<'a> = LinkRx;
    type TxToken<'a> = LinkTx<'a>;

    fn receive(&mut self, _ts: Instant) -> Option<(LinkRx, LinkTx<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((LinkRx(frame), LinkTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<LinkTx<'_>> {
        Some(LinkTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// ---------------------------------------------------------------------------
// Deterministic byte stream shared with the harness (splitmix64 keyed by seed and index)
// ---------------------------------------------------------------------------

fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn stream_byte(seed: u64, i: u64) -> u8 {
    (mix(seed ^ (i >> 3)) >> ((i & 7) * 8)) as u8
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv_update(mut h: u64, data: &[u8]) -> u64 {
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

// ---------------------------------------------------------------------------
// Peer state
// ---------------------------------------------------------------------------

struct Peer {
    v6: bool,
    auto_close_on_eof: bool,
    device: LinkDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,

    recv_enabled: bool,
    recv_limit: Option<u64>,
    echo: bool,
    echo_queue: VecDeque<u8>,
    rx_total: u64,
    rx_hash: u64,
    rx_finished: bool,

    gen_seed: u64,
    gen_total: u64,
    gen_done: u64,
    close_after_send: bool,
    tx_total: u64,
}

impl Peer {
    fn sock(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.handle)
    }

    fn take_rx(&mut self, max: usize) -> usize {
        let mut buf = vec![0u8; max.min(16 * 1024)];
        let mut got = 0;
        while got < max {
            let want = (max - got).min(buf.len());
            let sock = self.sockets.get_mut::<tcp::Socket>(self.handle);
            match sock.recv_slice(&mut buf[..want]) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    self.rx_total += n as u64;
                    self.rx_hash = fnv_update(self.rx_hash, &buf[..n]);
                    if self.echo {
                        self.echo_queue.extend(&buf[..n]);
                    }
                    got += n;
                }
            }
        }
        got
    }

    /// Application step: returns true if it did anything that may produce new output.
    fn app_step(&mut self) -> bool {
        let mut progress = false;

        if self.recv_enabled {
            let max = match self.recv_limit {
                Some(l) => l.saturating_sub(self.rx_total) as usize,
                None => usize::MAX / 2,
            };
            if self.take_rx(max) > 0 {
                progress = true;
            }
        }
        {
            let sock = self.sockets.get_mut::<tcp::Socket>(self.handle);
            if !self.rx_finished
                && !sock.may_recv()
                && !sock.can_recv()
                && matches!(
                    sock.state(),
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                        | tcp::State::FinWait2
                )
            {
                self.rx_finished = true;
                progress = true;
            }
        }

        loop {
            let sock = self.sockets.get_mut::<tcp::Socket>(self.handle);
            if !sock.may_send() || !sock.can_send() {
                break;
            }
            if !self.echo_queue.is_empty() {
                let (a, _) = self.echo_queue.as_slices();
                match sock.send_slice(a) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        self.tx_total += n as u64;
                        self.echo_queue.drain(..n);
                        progress = true;
                    }
                }
            } else if self.gen_done < self.gen_total {
                let room = sock.send_capacity() - sock.send_queue();
                let n = ((self.gen_total - self.gen_done) as usize).min(room).min(32 * 1024);
                if n == 0 {
                    break;
                }
                let mut chunk = vec![0u8; n];
                for (k, b) in chunk.iter_mut().enumerate() {
                    *b = stream_byte(self.gen_seed, self.gen_done + k as u64);
                }
                match sock.send_slice(&chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(m) => {
                        self.gen_done += m as u64;
                        self.tx_total += m as u64;
                        progress = true;
                    }
                }
            } else {
                break;
            }
        }

        let sock = self.sockets.get_mut::<tcp::Socket>(self.handle);
        let drained = self.echo_queue.is_empty() && self.gen_done >= self.gen_total;
        if self.close_after_send
            && self.gen_total > 0
            && self.gen_done >= self.gen_total
            && matches!(sock.state(), tcp::State::Established | tcp::State::CloseWait)
        {
            sock.close();
            self.close_after_send = false;
            progress = true;
        }
        if self.auto_close_on_eof && self.rx_finished && drained && matches!(sock.state(), tcp::State::CloseWait) {
            sock.close();
            progress = true;
        }
        progress
    }

    /// Poll the interface and run the application until nothing changes.
    fn pump(&mut self, now: Instant) {
        for _ in 0..100_000 {
            let r = self.iface.poll(now, &mut self.device, &mut self.sockets);
            let app = self.app_step();
            if r == smoltcp::iface::PollResult::None && !app {
                return;
            }
        }
        panic!("peer: pump did not quiesce");
    }

    fn poll_at(&mut self, now: Instant) -> i64 {
        match self.iface.poll_at(now, &self.sockets) {
            Some(t) => t.total_micros(),
            None => -1,
        }
    }
}

fn state_code(s: tcp::State) -> u8 {
    match s {
        tcp::State::Closed => 0,
        tcp::State::Listen => 1,
        tcp::State::SynSent => 2,
        tcp::State::SynReceived => 3,
        tcp::State::Established => 4,
        tcp::State::FinWait1 => 5,
        tcp::State::FinWait2 => 6,
        tcp::State::CloseWait => 7,
        tcp::State::Closing => 8,
        tcp::State::LastAck => 9,
        tcp::State::TimeWait => 10,
    }
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

fn read_msg(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)?;
    let len = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok((hdr[0], payload))
}

fn write_msg(w: &mut impl Write, ty: u8, payload: &[u8]) -> io::Result<()> {
    w.write_all(&[ty])?;
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.0[0];
        self.0 = &self.0[1..];
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes([self.0[0], self.0[1]]);
        self.0 = &self.0[2..];
        v
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.0[..4].try_into().unwrap());
        self.0 = &self.0[4..];
        v
    }
    fn u64(&mut self) -> u64 {
        let v = u64::from_le_bytes(self.0[..8].try_into().unwrap());
        self.0 = &self.0[8..];
        v
    }
}

/// `H` payload: v6 u8, rx_buf u32, tx_buf u32, mtu u16 (Ethernet frame size),
/// flags u8 (bit0 timestamps, bit1 nagle off, bit2 delayed ack off, bit3 auto-close on EOF),
/// cc u8 (0 none, 1 reno, 2 cubic), random_seed u64.
fn build_peer(p: &[u8]) -> Peer {
    let mut c = Cursor(p);
    let v6 = c.u8() != 0;
    let rx_buf = c.u32() as usize;
    let tx_buf = c.u32() as usize;
    let mtu = c.u16() as usize;
    let flags = c.u8();
    let cc = c.u8();
    let seed = c.u64();

    let mut device = LinkDevice { rx: VecDeque::new(), tx: Vec::new(), mtu };
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(PEER_MAC)));
    config.random_seed = seed;
    let mut iface = Interface::new(config, &mut device, Instant::from_micros(0));
    iface.update_ip_addrs(|addrs| {
        if v6 {
            let a = Ipv6Address::from(eui64_link_local(PEER_MAC));
            addrs.push(IpCidr::new(IpAddress::Ipv6(a), 64)).unwrap();
        } else {
            addrs.push(IpCidr::new(IpAddress::v4(PEER_V4[0], PEER_V4[1], PEER_V4[2], PEER_V4[3]), 24)).unwrap();
        }
    });

    let mut sock =
        tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; rx_buf]), tcp::SocketBuffer::new(vec![0u8; tx_buf]));
    if flags & 1 != 0 {
        sock.set_tsval_generator(Some(tsval));
    }
    if flags & 2 != 0 {
        sock.set_nagle_enabled(false);
    }
    if flags & 4 != 0 {
        sock.set_ack_delay(None);
    }
    sock.set_congestion_control(match cc {
        1 => tcp::CongestionControl::Reno,
        2 => tcp::CongestionControl::Cubic,
        _ => tcp::CongestionControl::None,
    });
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(sock);
    Peer {
        v6,
        auto_close_on_eof: flags & 8 != 0,
        device,
        iface,
        sockets,
        handle,
        recv_enabled: true,
        recv_limit: None,
        echo: false,
        echo_queue: VecDeque::new(),
        rx_total: 0,
        rx_hash: FNV_OFFSET,
        rx_finished: false,
        gen_seed: 0,
        gen_total: 0,
        gen_done: 0,
        close_after_send: false,
        tx_total: 0,
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut peer: Option<Peer> = None;

    loop {
        let (ty, payload) = match read_msg(&mut input) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut reply: Vec<u8> = Vec::new();
        match ty {
            b'H' => peer = Some(build_peer(&payload)),
            b'B' => return Ok(()),
            _ => {
                let p = peer.as_mut().expect("H must be the first message");
                let mut c = Cursor(&payload);
                match ty {
                    b'F' => p.device.rx.push_back(payload.clone()),
                    b'T' => {
                        let micros = c.u64() as i64;
                        TS_CLOCK_MS.store((micros / 1000) as u32, Ordering::Relaxed);
                        let now = Instant::from_micros(micros);
                        p.pump(now);
                        for f in p.device.tx.drain(..) {
                            write_msg(&mut out, b'F', &f)?;
                        }
                        reply.extend_from_slice(&p.poll_at(now).to_le_bytes());
                    }
                    // Split polling, for probes that need ingress without egress in between.
                    b'I' => {
                        let micros = c.u64() as i64;
                        TS_CLOCK_MS.store((micros / 1000) as u32, Ordering::Relaxed);
                        let now = Instant::from_micros(micros);
                        while p.iface.poll_ingress_single(now, &mut p.device, &mut p.sockets)
                            != smoltcp::iface::PollIngressSingleResult::None
                        {}
                    }
                    b'G' => {
                        let micros = c.u64() as i64;
                        TS_CLOCK_MS.store((micros / 1000) as u32, Ordering::Relaxed);
                        let now = Instant::from_micros(micros);
                        p.iface.poll_egress(now, &mut p.device, &mut p.sockets);
                        for f in p.device.tx.drain(..) {
                            write_msg(&mut out, b'F', &f)?;
                        }
                    }
                    b'P' => {
                        let micros = c.u64() as i64;
                        let now = Instant::from_micros(micros);
                        reply.extend_from_slice(&p.poll_at(now).to_le_bytes());
                    }
                    b'W' => {
                        let n = c.u32() as usize;
                        let data = vec![0x5a_u8; n];
                        let sent = p.sock().send_slice(&data).unwrap_or(0);
                        reply.extend_from_slice(&(sent as u32).to_le_bytes());
                    }
                    b'L' => {
                        let port = c.u16();
                        let r = p.sock().listen(port);
                        reply.push(r.is_ok() as u8);
                    }
                    b'K' => {
                        let remote_port = c.u16();
                        let local_port = c.u16();
                        let remote: IpAddress = if p.v6 {
                            IpAddress::Ipv6(Ipv6Address::from(eui64_link_local(HARNESS_MAC)))
                        } else {
                            IpAddress::v4(HARNESS_V4[0], HARNESS_V4[1], HARNESS_V4[2], HARNESS_V4[3])
                        };
                        let handle = p.handle;
                        let cx = p.iface.context();
                        let sock = p.sockets.get_mut::<tcp::Socket>(handle);
                        let r = sock.connect(cx, IpEndpoint::new(remote, remote_port), local_port);
                        reply.push(r.is_ok() as u8);
                    }
                    b'S' => {
                        p.gen_seed = c.u64();
                        p.gen_total = c.u64();
                        p.gen_done = 0;
                        p.close_after_send = c.u8() != 0;
                    }
                    b'E' => p.echo = c.u8() != 0,
                    b'R' => p.recv_enabled = c.u8() != 0,
                    b'M' => {
                        let l = c.u64();
                        p.recv_limit = if l == u64::MAX { None } else { Some(l) };
                    }
                    b'V' => {
                        let n = c.u32() as usize;
                        let got = p.take_rx(n);
                        reply.extend_from_slice(&(got as u32).to_le_bytes());
                    }
                    b'X' => p.sock().close(),
                    b'Z' => p.sock().abort(),
                    b'Q' => {
                        let (state, may_send, may_recv, can_send, can_recv, active, listening, sq, rq) = {
                            let s = p.sock();
                            (
                                state_code(s.state()),
                                s.may_send(),
                                s.may_recv(),
                                s.can_send(),
                                s.can_recv(),
                                s.is_active(),
                                s.is_listening(),
                                s.send_queue(),
                                s.recv_queue(),
                            )
                        };
                        reply.push(state);
                        let flags = (may_send as u8)
                            | (may_recv as u8) << 1
                            | (can_send as u8) << 2
                            | (can_recv as u8) << 3
                            | (active as u8) << 4
                            | (listening as u8) << 5
                            | (p.rx_finished as u8) << 6;
                        reply.push(flags);
                        reply.extend_from_slice(&p.rx_total.to_le_bytes());
                        reply.extend_from_slice(&p.rx_hash.to_le_bytes());
                        reply.extend_from_slice(&p.tx_total.to_le_bytes());
                        reply.extend_from_slice(&(sq as u32).to_le_bytes());
                        reply.extend_from_slice(&(rq as u32).to_le_bytes());
                    }
                    other => panic!("unknown message type {other}"),
                }
            }
        }
        write_msg(&mut out, b'A', &reply)?;
        out.flush()?;
    }
}
