use anyhow::Result;
use bitflags::bitflags;
use libbpf_rs::{query::MapInfoIter, Map, MapFlags};
use plain::Plain;
use serde::Serialize;
use serde_json::to_string_pretty;
use std::mem::{size_of, size_of_val};
use std::net::{Ipv4Addr, Ipv6Addr};

trait ToSerialize {
    fn to_serialize(&self) -> impl Serialize {}
}

impl<T> ToSerialize for T
where
    T: Clone + Serialize,
{
    fn to_serialize(&self) -> impl Serialize {
        self.clone()
    }
}

#[repr(C)]
#[derive(Default)]
struct PolicyKeyRaw {
    // len: u32,
    sec_label: u32,
    dport: u16,
    protocol: u8,
    egress: u8,
}

unsafe impl Plain for PolicyKeyRaw {}

#[derive(Serialize)]
struct PolicyKey {
    sec_label: u32,
    dport: u16,
    protocol: String,
    egress: bool,
}

impl ToSerialize for PolicyKeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        PolicyKey {
            sec_label: self.sec_label,
            dport: u16::from_be(self.dport),
            protocol: proto(self.protocol),
            egress: self.egress & 1 != 0,
        }
    }
}

bitflags! {
    #[derive(Default, Serialize)]
    struct PolicyEntryFlags : u8 {
        const DENY = 1;
        const WILDCARD_PROTOCOL = 1 << 1;
        const WILDCARD_DPORT = 1 << 2;
    }
}

#[repr(C)]
#[derive(Default)]
struct PolicyEntryRaw {
    proxy_port: u16,
    flags: PolicyEntryFlags,
    auth_type: u8,
    pad1: u16,
    pad2: u16,
    packets: u64,
    bytes: u64,
}

unsafe impl Plain for PolicyEntryRaw {}

impl ToSerialize for PolicyEntryRaw {
    fn to_serialize(&self) -> impl Serialize {
        PolicyEntry {
            proxy_port: u16::from_be(self.proxy_port),
            deny: self.flags.contains(PolicyEntryFlags::DENY),
            wildcard_protocol: self.flags.contains(PolicyEntryFlags::WILDCARD_PROTOCOL),
            wildcard_dport: self.flags.contains(PolicyEntryFlags::WILDCARD_DPORT),
            auth_type: self.auth_type,
            packets: self.packets,
            bytes: self.bytes,
        }
    }
}

#[derive(Serialize)]
struct PolicyEntry {
    proxy_port: u16,
    deny: bool,
    wildcard_protocol: bool,
    wildcard_dport: bool,
    auth_type: u8,
    packets: u64,
    bytes: u64,
}

#[repr(C)]
#[derive(Default)]
struct EndpointKeyRaw {
    addr: [u8; 16],
    family: u8,
    key: u8,
    cluster_id: u8,
}

unsafe impl Plain for EndpointKeyRaw {}

#[derive(Serialize)]
struct EndpointKey {
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
    family: u8,
    key: u8,
    cluster_id: u8,
}

impl ToSerialize for EndpointKeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        let ip4 = Ipv4Addr::from(u32::from_be_bytes(
            <[u8; 4]>::try_from(&self.addr[..4]).unwrap(),
        ));
        let ip6 = Ipv6Addr::from(self.addr);
        EndpointKey {
            ip4,
            ip6,
            family: self.family,
            key: self.key,
            cluster_id: self.cluster_id,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct TunnelKeyRaw {
    addr: [u8; 16],
    family: u8,
    cluster_id: u8,
}

unsafe impl Plain for TunnelKeyRaw {}

#[derive(Serialize)]
struct TunnelKey {
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
    family: u8,
    cluster_id: u8,
}

impl ToSerialize for TunnelKeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        let ip4 = Ipv4Addr::from(u32::from_be_bytes(
            <[u8; 4]>::try_from(&self.addr[..4]).unwrap(),
        ));
        let ip6 = Ipv6Addr::from(self.addr);
        TunnelKey {
            ip4,
            ip6,
            family: self.family,
            cluster_id: self.cluster_id,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct TunnelValueRaw {
    addr: [u8; 16],
    family: u8,
    key: u8,
    node_id: u16,
}

unsafe impl Plain for TunnelValueRaw {}

#[derive(Serialize)]
struct TunnelValue {
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
    family: u8,
    key: u8,
    node_id: u16,
}

impl ToSerialize for TunnelValueRaw {
    fn to_serialize(&self) -> impl Serialize {
        let ip4 = Ipv4Addr::from(u32::from_be_bytes(
            <[u8; 4]>::try_from(&self.addr[..4]).unwrap(),
        ));
        let ip6 = Ipv6Addr::from(self.addr);
        TunnelValue {
            ip4,
            ip6,
            family: self.family,
            key: self.key,
            node_id: self.node_id,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct EndpointInfoRaw {
    ifindex: u32,
    unused: u16,
    lxc_id: u16,
    flags: u32,
    mac: [u8; 6],
    node_mac: [u8; 6],
}

unsafe impl Plain for EndpointInfoRaw {}

#[derive(Serialize)]
struct EndpointInfo {
    ifindex: u32,
    unused: u16,
    lxc_id: u16,
    flags: u32,
    mac: String,
    node_mac: String,
}

impl ToSerialize for EndpointInfoRaw {
    fn to_serialize(&self) -> impl Serialize {
        let mac_vec: Vec<_> = self.mac.iter().map(|b| format!("{:x}", b)).collect();
        let mac = mac_vec.join(":");
        let node_mac_vec: Vec<_> = self.node_mac.iter().map(|b| format!("{:x}", b)).collect();
        let node_mac = node_mac_vec.join(":");
        EndpointInfo {
            ifindex: self.ifindex,
            unused: self.unused,
            lxc_id: self.lxc_id,
            flags: self.flags,
            mac,
            node_mac,
        }
    }
}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct EdtId {
    id: u64,
}

unsafe impl Plain for EdtId {}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct EdtInfo {
    bps: u64,
    t_last: u64,
    t_horizon_drop: u64,
}

#[repr(C)]
#[derive(Default)]
struct RemoteEndpointInfoRaw {
    sec_identity: u32,
    tunnel_endpoint: u32,
    node_id: u16,
    key: u8,
}

unsafe impl Plain for RemoteEndpointInfoRaw {}

#[derive(Serialize)]
struct RemoteEndpointInfo {
    sec_identity: u32,
    tunnel_endpoint: Ipv4Addr,
    node_id: u16,
    key: u8,
}

impl ToSerialize for RemoteEndpointInfoRaw {
    fn to_serialize(&self) -> impl Serialize {
        RemoteEndpointInfo {
            sec_identity: self.sec_identity,
            tunnel_endpoint: Ipv4Addr::from(u32::from_be(self.tunnel_endpoint)),
            node_id: self.node_id,
            key: self.key,
        }
    }
}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct AuthKey {
    local_sec_label: u32,
    remote_sec_label: u32,
    remote_node_id: u16,
    auth_type: u8,
}

unsafe impl Plain for AuthKey {}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct AuthInfo {
    expiration: u64,
}

unsafe impl Plain for AuthInfo {}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct MetricsKey {
    reason: u8,
    dir: u8,
}

unsafe impl Plain for MetricsKey {}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct MetricsValue {
    count: u64,
    bytes: u64,
}

unsafe impl Plain for MetricsValue {}

#[repr(C)]
#[derive(Default)]
struct EgressGwPolicyKeyRaw {
    saddr: u32,
    daddr: u32,
}

unsafe impl Plain for EgressGwPolicyKeyRaw {}

#[derive(Serialize)]
struct EgressGwPolicyKey {
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
}

impl ToSerialize for EgressGwPolicyKeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        let saddr = Ipv4Addr::from(u32::from_be(self.saddr));
        let daddr = Ipv4Addr::from(u32::from_be(self.daddr));
        EgressGwPolicyKey { saddr, daddr }
    }
}

#[repr(C)]
#[derive(Default)]
struct EgressGwPolicyEntryRaw {
    egress_ip: u32,
    gateway_ip: u32,
}

unsafe impl Plain for EgressGwPolicyEntryRaw {}

#[derive(Serialize)]
struct EgressGwPolicyEntry {
    egress_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
}

impl ToSerialize for EgressGwPolicyEntryRaw {
    fn to_serialize(&self) -> impl Serialize {
        let egress_ip = Ipv4Addr::from(u32::from_be(self.egress_ip));
        let gateway_ip = Ipv4Addr::from(u32::from_be(self.gateway_ip));
        EgressGwPolicyEntry {
            egress_ip,
            gateway_ip,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Srv6VrfKey4Raw {
    src_ip: u32,
    dst_cidr: u32,
}

unsafe impl Plain for Srv6VrfKey4Raw {}

#[derive(Serialize)]
struct Srv6VrfKey4 {
    src_ip: Ipv4Addr,
    dst_cidr: Ipv4Addr,
}

impl ToSerialize for Srv6VrfKey4Raw {
    fn to_serialize(&self) -> impl Serialize {
        let src_ip = Ipv4Addr::from(u32::from_be(self.src_ip));
        let dst_cidr = Ipv4Addr::from(u32::from_be(self.dst_cidr));
        Srv6VrfKey4 { src_ip, dst_cidr }
    }
}

#[repr(C)]
#[derive(Default)]
struct Srv6VrfKey6Raw {
    src_ip: [u8; 16],
    dst_cidr: [u8; 16],
}

unsafe impl Plain for Srv6VrfKey6Raw {}

#[derive(Serialize)]
struct Srv6VrfKey6 {
    src_ip: Ipv6Addr,
    dst_cidr: Ipv6Addr,
}

impl ToSerialize for Srv6VrfKey6Raw {
    fn to_serialize(&self) -> impl Serialize {
        let src_ip = Ipv6Addr::from(self.src_ip);
        let dst_cidr = Ipv6Addr::from(self.dst_cidr);
        Srv6VrfKey6 { src_ip, dst_cidr }
    }
}

#[repr(C)]
#[derive(Default)]
struct Srv6PolicyKey4Raw {
    vrf_id: u32,
    dst_cidr: u32,
}

unsafe impl Plain for Srv6PolicyKey4Raw {}

#[derive(Serialize)]
struct Srv6PolicyKey4 {
    vrf_id: u32,
    dst_cidr: Ipv4Addr,
}

impl ToSerialize for Srv6PolicyKey4Raw {
    fn to_serialize(&self) -> impl Serialize {
        let dst_cidr = Ipv4Addr::from(u32::from_be(self.dst_cidr));
        Srv6PolicyKey4 {
            vrf_id: self.vrf_id,
            dst_cidr,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Srv6PolicyKey6Raw {
    vrf_id: u32,
    dst_cidr: [u8; 16],
}

unsafe impl Plain for Srv6PolicyKey6Raw {}

#[derive(Serialize)]
struct Srv6PolicyKey6 {
    vrf_id: u32,
    dst_cidr: Ipv6Addr,
}

impl ToSerialize for Srv6PolicyKey6Raw {
    fn to_serialize(&self) -> impl Serialize {
        let dst_cidr = Ipv6Addr::from(self.dst_cidr);
        Srv6PolicyKey6 {
            vrf_id: self.vrf_id,
            dst_cidr,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Srv6Ipv4_2tupleRaw {
    src: u32,
    dst: u32,
}

unsafe impl Plain for Srv6Ipv4_2tupleRaw {}

#[derive(Serialize)]
struct Srv6Ipv4_2tuple {
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl ToSerialize for Srv6Ipv4_2tupleRaw {
    fn to_serialize(&self) -> impl Serialize {
        let src = Ipv4Addr::from(u32::from_be(self.src));
        let dst = Ipv4Addr::from(u32::from_be(self.dst));
        Srv6Ipv4_2tuple { src, dst }
    }
}

#[repr(C)]
#[derive(Default)]
struct Srv6Ipv6_2tupleRaw {
    src: [u8; 16],
    dst: [u8; 16],
}

unsafe impl Plain for Srv6Ipv6_2tupleRaw {}

#[derive(Serialize)]
struct Srv6Ipv6_2tuple {
    src: Ipv6Addr,
    dst: Ipv6Addr,
}

impl ToSerialize for Srv6Ipv6_2tupleRaw {
    fn to_serialize(&self) -> impl Serialize {
        let src = Ipv6Addr::from(self.src);
        let dst = Ipv6Addr::from(self.dst);
        Srv6Ipv6_2tuple { src, dst }
    }
}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct VtepKey {
    vtep_ip: u32,
}

unsafe impl Plain for VtepKey {}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct VtepValue {
    vtep_mac: u64,
    tunnel_endpoint: u32,
}

unsafe impl Plain for VtepValue {}

// NOTIFY_COMMON_HDR
// _type: u8,
// subtype: u8,
// source: u16,
// hash: u32,

// NOTIFY_CAPTURE_HDR
// _type: u8,
// subtype: u8,
// source: u16,
// hash: u32,
// len_orig: u32,
// len_cap: u16,
// version: u16,

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct EncryptConfig {
    encrypt_key: u8,
}

unsafe impl Plain for EncryptConfig {}

fn proto(proto: u8) -> String {
    match proto {
        0 => "HOPOPT",
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        43 => "IPv6-Route",
        44 => "IPv6-Frag",
        58 => "IPv6-ICMP",
        132 => "SCTP",
        _ => "",
    }
    .to_string()
}

#[repr(C)]
#[derive(Default)]
struct Ipv6CtTupleRaw {
    daddr: [u8; 16],
    saddr: [u8; 16],
    dport: u16,
    sport: u16,
    nexthdr: u8,
    flags: u8,
}

unsafe impl Plain for Ipv6CtTupleRaw {}

#[derive(Serialize)]
struct Ipv6CtTuple {
    daddr: Ipv6Addr,
    saddr: Ipv6Addr,
    dport: u16,
    sport: u16,
    nexthdr: String,
    flags: u8,
}

impl ToSerialize for Ipv6CtTupleRaw {
    fn to_serialize(&self) -> impl Serialize {
        let daddr = Ipv6Addr::from(self.daddr);
        let saddr = Ipv6Addr::from(self.saddr);
        let dport = u16::from_be(self.dport);
        let sport = u16::from_be(self.sport);
        Ipv6CtTuple {
            daddr,
            saddr,
            dport,
            sport,
            nexthdr: proto(self.nexthdr),
            flags: self.flags,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Ipv4CtTupleRaw {
    daddr: u32,
    saddr: u32,
    dport: u16,
    sport: u16,
    nexthdr: u8,
    flags: u8,
}

unsafe impl Plain for Ipv4CtTupleRaw {}

impl Ipv4CtTupleRaw {
    fn serialize(&self) -> Ipv4CtTuple {
        let daddr = Ipv4Addr::from(u32::from_be(self.daddr));
        let saddr = Ipv4Addr::from(u32::from_be(self.saddr));
        let dport = u16::from_be(self.dport);
        let sport = u16::from_be(self.sport);
        Ipv4CtTuple {
            daddr,
            saddr,
            dport,
            sport,
            nexthdr: proto(self.nexthdr),
            flags: self.flags,
        }
    }
}

#[derive(Serialize)]
struct Ipv4CtTuple {
    daddr: Ipv4Addr,
    saddr: Ipv4Addr,
    dport: u16,
    sport: u16,
    nexthdr: String,
    flags: u8,
}

impl ToSerialize for Ipv4CtTupleRaw {
    fn to_serialize(&self) -> impl Serialize {
        self.serialize()
    }
}

bitflags! {
    #[derive(Default)]
    struct CtEntryFlags: u16 {
        const RX_CLOSING = 1;
        const TX_CLOSING = 1 << 1;
        const NAT46 = 1 << 2;
        const LB_LOOPBACK = 1 << 3;
        const SEEN_NON_SYN = 1 << 4;
        const NODE_PORT = 1 << 5;
        const PROXY_REDIRECT = 1 << 6;
        const DSR = 1 << 7;
        const FROM_L7LB = 1 << 8;
        const FROM_TUNNEL = 1 << 10;
    }
}

bitflags! {
    #[derive(Default, Serialize, Clone)]
    struct TCPFlags: u8 {
        const FIN = 1;
        const SYN = 1 << 1;
        const RST = 1 << 2;
        const PSH = 1 << 3;
        const ACK = 1 << 4;
        const URG = 1 << 5;
    }
}

#[repr(C)]
#[derive(Default)]
struct CtEntryRaw {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    lifetime: u32,
    flags: CtEntryFlags,
    rev_nat_index: u16,
    ifindex: u16,
    tx_flags_seen: TCPFlags,
    rx_flags_seen: TCPFlags,
    src_sec_id: u32,
    last_tx_report: u32,
    last_rx_report: u32,
}

unsafe impl Plain for CtEntryRaw {}

#[derive(Serialize)]
struct CtEntry {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    lifetime: u32,
    rx_closing: bool,
    tx_closing: bool,
    nat46: bool,
    lb_loopback: bool,
    seen_non_syn: bool,
    node_port: bool,
    proxy_redirect: bool,
    dsr: bool,
    from_l7lb: bool,
    from_tunnel: bool,
    rev_nat_index: u16,
    ifindex: u16,
    tx_flags_seen: TCPFlags,
    rx_flags_seen: TCPFlags,
    src_sec_id: u32,
    last_tx_report: u32,
    last_rx_report: u32,
}

impl ToSerialize for CtEntryRaw {
    fn to_serialize(&self) -> impl Serialize {
        let flags = &self.flags;
        let rx_closing = flags.contains(CtEntryFlags::RX_CLOSING);
        let tx_closing = flags.contains(CtEntryFlags::TX_CLOSING);
        let nat46 = flags.contains(CtEntryFlags::NAT46);
        let lb_loopback = flags.contains(CtEntryFlags::LB_LOOPBACK);
        let seen_non_syn = flags.contains(CtEntryFlags::SEEN_NON_SYN);
        let node_port = flags.contains(CtEntryFlags::NODE_PORT);
        let proxy_redirect = flags.contains(CtEntryFlags::PROXY_REDIRECT);
        let dsr = flags.contains(CtEntryFlags::DSR);
        let from_l7lb = flags.contains(CtEntryFlags::FROM_L7LB);
        let from_tunnel = flags.contains(CtEntryFlags::FROM_TUNNEL);
        CtEntry {
            rx_packets: self.rx_packets,
            rx_bytes: self.rx_bytes,
            tx_packets: self.tx_packets,
            tx_bytes: self.tx_bytes,
            lifetime: self.lifetime,
            rx_closing,
            tx_closing,
            nat46,
            lb_loopback,
            seen_non_syn,
            node_port,
            proxy_redirect,
            dsr,
            from_l7lb,
            from_tunnel,
            rev_nat_index: self.rev_nat_index,
            ifindex: self.ifindex,
            tx_flags_seen: self.tx_flags_seen.clone(),
            rx_flags_seen: self.rx_flags_seen.clone(),
            src_sec_id: self.src_sec_id,
            last_tx_report: self.last_tx_report,
            last_rx_report: self.last_rx_report,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Lb6KeyRaw {
    address: [u8; 16],
    dport: u16,
    backend_slot: u16,
    proto: u8,
    scope: u8,
}

unsafe impl Plain for Lb6KeyRaw {}

#[derive(Serialize)]
struct Lb6Key {
    address: Ipv6Addr,
    dport: u16,
    backend_slot: u16,
    proto: u8,
    scope: String,
}

impl ToSerialize for Lb6KeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv6Addr::from(self.address);
        Lb6Key {
            address,
            dport: u16::from_be(self.dport),
            backend_slot: self.backend_slot,
            proto: self.proto,
            scope: match self.scope {
                0 => "LB_LOOKUP_SCOPE_EXT",
                1 => "LB_LOOKUP_SCOPE_INT",
                _ => "",
            }
            .to_string(),
        }
    }
}

bitflags! {
    #[derive(Default, Serialize, Clone)]
    struct ServiceFlags: u8 {
        const SVC_FLAG_EXTERNAL_IP  = (1 << 0);  /* External IPs */
        const SVC_FLAG_NODEPORT     = (1 << 1);  /* NodePort service */
        const SVC_FLAG_EXT_LOCAL_SCOPE = (1 << 2); /* externalTrafficPolicy=Local */
        const SVC_FLAG_HOSTPORT     = (1 << 3);  /* hostPort forwarding */
        const SVC_FLAG_AFFINITY     = (1 << 4);  /* sessionAffinity=clientIP */
        const SVC_FLAG_LOADBALANCER = (1 << 5);  /* LoadBalancer service */
        const SVC_FLAG_ROUTABLE     = (1 << 6);  /* Not a surrogate/ClusterIP entry */
        const SVC_FLAG_SOURCE_RANGE = (1 << 7);  /* Check LoadBalancer source range */
    }

    #[derive(Default, Serialize, Clone)]
    struct ServiceFlags2: u8 {
        const SVC_FLAG_LOCALREDIRECT  = (1 << 0);  /* local redirect */
        const SVC_FLAG_NAT_46X64      = (1 << 1);  /* NAT-46/64 entry */
        const SVC_FLAG_L7LOADBALANCER = (1 << 2);  /* tproxy redirect to local l7 loadbalancer */
        const SVC_FLAG_LOOPBACK       = (1 << 3);  /* hostport with a loopback hostIP */
        const SVC_FLAG_INT_LOCAL_SCOPE = (1 << 4); /* internalTrafficPolicy=Local */
        const SVC_FLAG_TWO_SCOPES     = (1 << 5);  /* two sets of backends are used for external/internal connections */
    }
}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct Lb6Service {
    backend_id: u32,
    count: u16,
    rev_nat_index: u16,
    flags: ServiceFlags,
    flags2: ServiceFlags2,
}

unsafe impl Plain for Lb6Service {}

#[repr(C)]
#[derive(Default)]
struct Lb6BackendRaw {
    address: [u8; 16],
    port: u16,
    proto: u8,
    flags: u8,
    cluster_id: u8,
}

unsafe impl Plain for Lb6Backend {}

#[derive(Serialize)]
struct Lb6Backend {
    address: Ipv6Addr,
    port: u16,
    proto: u8,
    flags: u8,
    cluster_id: u8,
}

impl ToSerialize for Lb6BackendRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv6Addr::from(self.address);
        Lb6Backend {
            address,
            port: u16::from_be(self.port),
            proto: self.proto,
            flags: self.flags,
            cluster_id: self.cluster_id,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Lb6ReverseNatRaw {
    address: [u8; 16],
    port: u16,
}

unsafe impl Plain for Lb6ReverseNatRaw {}

#[derive(Serialize)]
struct Lb6ReverseNat {
    address: Ipv6Addr,
    port: u16,
}

impl ToSerialize for Lb6ReverseNatRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv6Addr::from(self.address);
        Lb6ReverseNat {
            address,
            port: u16::from_be(self.port),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Ipv6RevnatTupleRaw {
    cookie: u64,
    address: [u8; 16],
    port: u16,
}

unsafe impl Plain for Ipv6RevnatTupleRaw {}

#[derive(Serialize)]
struct Ipv6RevnatTuple {
    cookie: u64,
    address: Ipv6Addr,
    port: u16,
}

impl ToSerialize for Ipv6RevnatTupleRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv6Addr::from(self.address);
        Ipv6RevnatTuple {
            cookie: self.cookie,
            address,
            port: u16::from_be(self.port),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Ipv6RevnatEntryRaw {
    address: [u8; 16],
    port: u16,
    rev_nat_index: u16,
}

unsafe impl Plain for Ipv6RevnatEntryRaw {}

#[derive(Serialize)]
struct Ipv6RevnatEntry {
    address: Ipv6Addr,
    port: u16,
    rev_nat_index: u16,
}

impl ToSerialize for Ipv6RevnatEntryRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv6Addr::from(self.address);
        Ipv6RevnatEntry {
            address,
            port: u16::from_be(self.port),
            rev_nat_index: self.rev_nat_index,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Lb4KeyRaw {
    address: u32,
    dport: u16,
    backend_slot: u16,
    proto: u8,
    scope: u8,
}

unsafe impl Plain for Lb4KeyRaw {}

#[derive(Serialize)]
struct Lb4Key {
    address: Ipv4Addr,
    dport: u16,
    backend_slot: u16,
    proto: String,
    scope: String,
}

impl ToSerialize for Lb4KeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv4Addr::from(u32::from_be(self.address));
        Lb4Key {
            address,
            dport: u16::from_be(self.dport),
            backend_slot: self.backend_slot,
            proto: proto(self.proto),
            scope: match self.scope {
                0 => "LB_LOOKUP_SCOPE_EXT",
                1 => "LB_LOOKUP_SCOPE_INT",
                _ => "",
            }
            .to_string(),
        }
    }
}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct Lb4Service {
    backend_id: u32,
    count: u16,
    rev_nat_index: u16,
    flags: ServiceFlags,
    flags2: ServiceFlags2,
}

unsafe impl Plain for Lb4Service {}

#[repr(C)]
#[derive(Default)]
struct Lb4BackendRaw {
    address: u32,
    port: u16,
    proto: u8,
    flags: u8,
    cluster_id: u8,
}

unsafe impl Plain for Lb4BackendRaw {}

#[derive(Serialize)]
struct Lb4Backend {
    address: Ipv4Addr,
    port: u16,
    proto: String,
    flags: u8,
    cluster_id: u8,
}

impl ToSerialize for Lb4BackendRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv4Addr::from(u32::from_be(self.address));
        Lb4Backend {
            address,
            port: u16::from_be(self.port),
            proto: proto(self.proto),
            flags: self.flags,
            cluster_id: self.cluster_id,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Lb4ReverseNatRaw {
    address: u32,
    port: u16,
}

unsafe impl Plain for Lb4ReverseNatRaw {}

#[derive(Serialize)]
struct Lb4ReverseNat {
    address: Ipv4Addr,
    port: u16,
}

impl ToSerialize for Lb4ReverseNatRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv4Addr::from(u32::from_be(self.address));
        Lb4ReverseNat {
            address,
            port: u16::from_be(self.port),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Ipv4RevnatTupleRaw {
    cookie: u64,
    address: u32,
    port: u16,
}

unsafe impl Plain for Ipv4RevnatTupleRaw {}

#[derive(Serialize)]
struct Ipv4RevnatTuple {
    cookie: u64,
    address: Ipv4Addr,
    port: u16,
}

impl ToSerialize for Ipv4RevnatTupleRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv4Addr::from(u32::from_be(self.address));
        Ipv4RevnatTuple {
            cookie: self.cookie,
            address,
            port: u16::from_be(self.port),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Ipv4RevnatEntryRaw {
    address: u32,
    port: u16,
    rev_nat_index: u16,
}

unsafe impl Plain for Ipv4RevnatEntryRaw {}

#[derive(Serialize)]
struct Ipv4RevnatEntry {
    address: Ipv4Addr,
    port: u16,
    rev_nat_index: u16,
}

impl ToSerialize for Ipv4RevnatEntryRaw {
    fn to_serialize(&self) -> impl Serialize {
        let address = Ipv4Addr::from(u32::from_be(self.address));
        Ipv4RevnatEntry {
            address,
            port: u16::from_be(self.port),
            rev_nat_index: self.rev_nat_index,
        }
    }
}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct Lb4AffinityClientId {
    client_ip: u32,
    client_cookie: u64,
}

unsafe impl Plain for Lb4AffinityClientId {}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct Lb4AffinityKey {
    client_id: Lb4AffinityClientId,
    rev_nat_id: u16,
    netns_cookie: u8,
}

unsafe impl Plain for Lb4AffinityKey {}

#[repr(C)]
#[derive(Default, Serialize, Clone)]
struct LbAffinityVal {
    last_used: u64,
    backend_id: u32,
}

unsafe impl Plain for LbAffinityVal {}

bitflags! {
    #[derive(Default)]
    struct CtStateFlags: u16 {
        const LOOPBACK = 1;
        const NODE_PORT = 1 << 1;
        const DSR = 1 << 2;
        const SYN = 1 << 3;
        const PROXY_REDIRECT = 1 << 4;
        const FROM_L7LB = 1 << 5;
        const FROM_TUNNEL = 1 << 7;
    }
}

#[repr(C)]
#[derive(Default)]
struct CtStateRaw {
    rev_nat_index: u16,
    flags: CtStateFlags,
    addr: u32,
    svc_addr: u32,
    src_sec_id: u32,
    ifindex: u16,
    backend_id: u32,
}

unsafe impl Plain for CtStateRaw {}

impl CtStateRaw {
    fn serialize(&self) -> CtState {
        let addr = Ipv4Addr::from(u32::from_be(self.addr));
        let svc_addr = Ipv4Addr::from(u32::from_be(self.svc_addr));
        let flags = &self.flags;
        CtState {
            rev_nat_index: self.rev_nat_index,
            loopback: flags.contains(CtStateFlags::LOOPBACK),
            node_port: flags.contains(CtStateFlags::NODE_PORT),
            dsr: flags.contains(CtStateFlags::DSR),
            syn: flags.contains(CtStateFlags::SYN),
            proxy_redirect: flags.contains(CtStateFlags::PROXY_REDIRECT),
            from_l7lb: flags.contains(CtStateFlags::FROM_L7LB),
            from_tunnel: flags.contains(CtStateFlags::FROM_TUNNEL),
            addr,
            svc_addr,
            src_sec_id: self.src_sec_id,
            ifindex: self.ifindex,
            backend_id: self.backend_id,
        }
    }
}

#[derive(Serialize)]
struct CtState {
    rev_nat_index: u16,
    loopback: bool,
    node_port: bool,
    dsr: bool,
    syn: bool,
    proxy_redirect: bool,
    from_l7lb: bool,
    from_tunnel: bool,
    addr: Ipv4Addr,
    svc_addr: Ipv4Addr,
    src_sec_id: u32,
    ifindex: u16,
    backend_id: u32,
}

impl ToSerialize for CtStateRaw {
    fn to_serialize(&self) -> impl Serialize {
        self.serialize()
    }
}

#[repr(C)]
#[derive(Default)]
struct Lb4SrcRangeKeyRaw {
    rev_nat_id: u16,
    pad: u16,
    addr: u32,
}

unsafe impl Plain for Lb4SrcRangeKeyRaw {}

#[derive(Serialize)]
struct Lb4SrcRangeKey {
    rev_nat_id: u16,
    addr: Ipv4Addr,
}

impl ToSerialize for Lb4SrcRangeKeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        let addr = Ipv4Addr::from(u32::from_be(self.addr));
        Lb4SrcRangeKey {
            rev_nat_id: self.rev_nat_id,
            addr,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct LpmV4KeyRaw {
    addr: u32,
}

unsafe impl Plain for LpmV4KeyRaw {}

#[derive(Serialize)]
struct LpmV4Key {
    addr: Ipv4Addr,
}

impl ToSerialize for LpmV4KeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        LpmV4Key {
            addr: Ipv4Addr::from(u32::from_be(self.addr)),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct NatEntry {
    created: u64,
    host_local: u64,
    pad1: u64,
    pad2: u64,
}

unsafe impl Plain for NatEntry {}

#[repr(C)]
#[derive(Default)]
struct Ipv4NatEntryRaw {
    common: NatEntry,
    to_addr: u32,
    to_port: u16,
}

unsafe impl Plain for Ipv4NatEntryRaw {}

#[repr(C)]
#[derive(Serialize)]
struct Ipv4NatEntry {
    created: u64,
    host_local: u64,
    to_addr: Ipv4Addr,
    to_port: u16,
}

impl ToSerialize for Ipv4NatEntryRaw {
    fn to_serialize(&self) -> impl Serialize {
        let to_addr = Ipv4Addr::from(u32::from_be(self.to_addr));
        Ipv4NatEntry {
            created: self.common.created,
            host_local: self.common.host_local,
            to_addr,
            to_port: u16::from_be(self.to_port),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct IpcacheKeyRaw {
    pad0: u32,
    pad1: u16,
    cluster_id: u8,
    family: u8,
    addr: [u8; 16],
}

unsafe impl Plain for IpcacheKeyRaw {}

#[derive(Serialize)]
struct IpcacheKey {
    cluster_id: u8,
    family: u8,
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
}

impl ToSerialize for IpcacheKeyRaw {
    fn to_serialize(&self) -> impl Serialize {
        let ip4 = Ipv4Addr::from(u32::from_be_bytes(
            <[u8; 4]>::try_from(&self.addr[..4]).unwrap(),
        ));
        let ip6 = Ipv6Addr::from(self.addr);
        IpcacheKey {
            cluster_id: self.cluster_id,
            family: self.family,
            ip4,
            ip6,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct CtBuffer4Raw {
    tuple: Ipv4CtTupleRaw,
    ct_state: CtStateRaw,
    monitor: u32,
    ret: u32,
}

unsafe impl Plain for CtBuffer4Raw {}

#[derive(Serialize)]
struct CtBuffer4 {
    tuple: Ipv4CtTuple,
    ct_state: CtState,
    monitor: u32,
    ret: u32,
}

impl ToSerialize for CtBuffer4Raw {
    fn to_serialize(&self) -> impl Serialize {
        CtBuffer4 {
            tuple: self.tuple.serialize(),
            ct_state: self.ct_state.serialize(),
            monitor: self.monitor,
            ret: self.ret,
        }
    }
}

macro_rules! dump_percpu {
    ($name:expr, $key:ty, $value:ty) => {{
        let map_info_iter = MapInfoIter::default();
        for map_info in map_info_iter {
            if map_info.name.starts_with($name) {
                println!("map id {} name {}", map_info.id, map_info.name);
                let map = Map::from_map_id(map_info.id)?;
                for mut key in map.keys() {
                    let mut _key = <$key>::default();
                    let mut values = map.lookup_percpu(&key, MapFlags::empty())?.unwrap();
                    key.extend(vec![0; size_of_val(&_key).saturating_sub(key.len())]);
                    _key.copy_from_bytes(&key).unwrap();
                    println!("key: {}", to_string_pretty(&_key.to_serialize())?);
                    for (i, value) in values.iter_mut().enumerate() {
                        let mut _value = <$value>::default();
                        value.extend(vec![0; size_of_val(&_value).saturating_sub(value.len())]);
                        _value.copy_from_bytes(&value).unwrap();
                        println!("{}: {}", i, to_string_pretty(&_value.to_serialize())?);
                    }
                }
            }
        }
    }};
    ($name:expr, $value:ty) => {{
        let map_info_iter = MapInfoIter::default();
        for map_info in map_info_iter {
            if map_info.name.starts_with($name) {
                println!("map id {} name {}", map_info.id, map_info.name);
                let map = Map::from_map_id(map_info.id)?;
                for key in map.keys() {
                    println!(
                        "key: {}",
                        u32::from_be_bytes(key.clone().try_into().unwrap())
                    );
                    for (i, value) in map
                        .lookup_percpu(&key, MapFlags::empty())?
                        .unwrap()
                        .iter_mut()
                        .enumerate()
                    {
                        let mut _value = <$value>::default();
                        value.extend(vec![0; size_of_val(&_value).saturating_sub(value.len())]);
                        _value.copy_from_bytes(&value).unwrap();
                        println!("{}: {}", i, to_string_pretty(&_value.to_serialize())?);
                    }
                }
            }
        }
    }};
}

macro_rules! dump {
    ($name:expr, $key:ty, $value:ty $(, $key_size:expr)?) => {{
        let map_info_iter = MapInfoIter::default();
        for map_info in map_info_iter {
            if map_info.name.starts_with($name) $(&& map_info.key_size == $key_size)? {
                println!("map id {} name {}", map_info.id, map_info.name);
                let map = Map::from_map_id(map_info.id)?;
                for mut key in map.keys() {
                    let mut _key = <$key>::default();
                    let mut value = map.lookup(&key, MapFlags::empty())?.unwrap();
                    key.extend(vec![0; size_of_val(&_key).saturating_sub(key.len())]);
                    _key.copy_from_bytes(&key).unwrap();
                    println!("key: {}", to_string_pretty(&_key.to_serialize())?);
                    let mut _value = <$value>::default();
                    value.extend(vec![0; size_of_val(&_value).saturating_sub(value.len())]);
                    _value.copy_from_bytes(&value).unwrap();
                    println!("value: {}", to_string_pretty(&_value.to_serialize())?);
                }
            }
        }
    }};
    ($name:expr, $value:ty $(, $key_size:expr)?) => {{
        let map_info_iter = MapInfoIter::default();
        for map_info in map_info_iter {
            if map_info.name.starts_with($name) $(&& map_info.key_size == $key_size)? {
                println!("map id {} name {}", map_info.id, map_info.name);
                let map = Map::from_map_id(map_info.id)?;
                for key in map.keys() {
                    let mut _key = key.clone();
                    _key.extend(vec![0; size_of::<usize>().saturating_sub(_key.len())]);
                    println!("key: {}", usize::from_le_bytes(_key.try_into().unwrap()));
                    let mut value = map.lookup(&key, MapFlags::empty())?.unwrap();
                    let mut _value = <$value>::default();
                    value.extend(vec![0; size_of_val(&_value).saturating_sub(value.len())]);
                    _value.copy_from_bytes(&value).unwrap();
                    println!("value: {}", to_string_pretty(&_value.to_serialize())?);
                }
            }
        }
    }};
}

pub fn dump(name: &str) -> Result<()> {
    match name {
        "metrics" => dump_percpu!("cilium_metrics", MetricsKey, MetricsValue),
        "policy" => dump!("cilium_policy_", PolicyKeyRaw, PolicyEntryRaw),
        "tunnel" => dump!("cilium_tunnel_m", TunnelKeyRaw, TunnelValueRaw),
        "encrypt" => dump!("cilium_encrypt_", EncryptConfig),
        "ct4_glob" => dump!("cilium_ct4_glob", Ipv4CtTupleRaw, CtEntryRaw),
        "ct_any4" => dump!("cilium_ct_any4_", Ipv4CtTupleRaw, CtEntryRaw),
        "lb4_reverse_nat" => dump!("cilium_lb4_reve", Lb4ReverseNatRaw, 2),
        "lb4_reverse_nat_sk" => dump!(
            "cilium_lb4_reve",
            Ipv4RevnatTupleRaw,
            Ipv4RevnatEntryRaw,
            16
        ),
        "lb4_services" => dump!("cilium_lb4_serv", Lb4KeyRaw, Lb4Service),
        "lb4_backend" => dump!("cilium_lb4_back", Lb4BackendRaw),
        "lb_affinity" => dump!("cilium_lb_affin", Lb4AffinityKey, LbAffinityVal),
        "snat_v4" => dump!("cilium_snat_v4_", Ipv4CtTupleRaw, Ipv4NatEntryRaw),
        "ipcache" => dump!("cilium_ipcache", IpcacheKeyRaw, RemoteEndpointInfoRaw),
        "ct_buffer4" => dump_percpu!("cilium_tail_cal", CtBuffer4Raw),
        _ => (),
    }
    Ok(())
}
