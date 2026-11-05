//! DnsDiscoveryProvider —— 通过 DNS 查询动态发现上游端点。
//!
//! # 为什么手写 DNS 客户端
//!
//! 只需要的两种查询（A/AAAA 与 SRV）报文格式固定，手写后可保持
//! `gateway-discovery` 零第三方网络依赖，也避免把异步解析器引入数据面。
//!
//! # 支持范围
//!
//! - `A` / `AAAA`：解析出 IP，端口取配置的 `default_port`
//! - `SRV`：直接解析出 `host:port` 与权重（权重映射到 EndpointConfig.weight）
//!
//! # 超时与失败
//!
//! 单次查询有硬超时；失败返回 `DiscoveryError::Provider`，
//! 由上层决定是否沿用上一次成功结果（Last Known Good）。

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use gateway_core::{
    DiscoveryError, DiscoveryHealth, EndpointConfig, ServiceDiscoveryProvider,
};

/// DNS 查询类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryKind {
    /// A / AAAA 记录（主机地址）
    Address,
    /// SRV 记录（服务地址 + 端口 + 权重）
    Srv,
}

/// DNS Provider 配置。
#[derive(Debug, Clone)]
pub struct DnsDiscoveryConfig {
    /// 查询域名，例如 `backend.default.svc.cluster.local`
    pub domain: String,
    /// A 记录模式下的默认端口
    pub default_port: u16,
    /// 递归解析服务器地址，例如 `127.0.0.1:53`
    pub resolver: SocketAddr,
    /// 单次查询超时
    pub timeout: Duration,
    /// 查询类型
    pub kind: DnsQueryKind,
}

/// DNS 服务发现 Provider。
pub struct DnsDiscoveryProvider {
    /// 配置（不可变，可跨请求共享）
    config: DnsDiscoveryConfig,
}

impl DnsDiscoveryProvider {
    /// 构造 Provider。
    pub fn new(config: DnsDiscoveryConfig) -> Self {
        Self { config }
    }

    /// 一次 DNS 查询：返回解析到的端点列表。
    ///
    /// 报文构造与应答解析都在此函数内完成，无 unwrap/expect。
    async fn query(&self) -> Result<Vec<EndpointConfig>, DiscoveryError> {
        // 每个查询使用递增的 16 位 ID（DNS 协议要求匹配请求/应答）
        static QUERY_ID: std::sync::atomic::AtomicU16 =
            std::sync::atomic::AtomicU16::new(1);
        let id = QUERY_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let qtype: u16 = match self.config.kind {
            DnsQueryKind::Address => 1, // A
            DnsQueryKind::Srv => 33,    // SRV
        };

        // 构造查询报文
        let mut packet: Vec<u8> = Vec::with_capacity(64);
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        push_qname(&mut packet, &self.config.domain)?;
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

        // UDP 查询（绑定任意本地端口）
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DiscoveryError::Provider(format!("dns bind failed: {e}")))?;
        socket
            .send_to(&packet, self.config.resolver)
            .await
            .map_err(|e| DiscoveryError::Provider(format!("dns send failed: {e}")))?;

        let mut buf = vec![0u8; 4096];
        let received = tokio::time::timeout(self.config.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| DiscoveryError::Provider("dns query timed out".to_string()))?
            .map_err(|e| DiscoveryError::Provider(format!("dns recv failed: {e}")))?;

        let (len, _peer) = received;
        buf.truncate(len);
        parse_response(&buf, id, self.config.kind, self.config.default_port)
    }
}

#[async_trait]
impl ServiceDiscoveryProvider for DnsDiscoveryProvider {
    async fn resolve(&self, _upstream_id: &str) -> Result<Vec<EndpointConfig>, DiscoveryError> {
        self.query().await
    }

    async fn health(&self) -> DiscoveryHealth {
        // DNS Provider 自身无持久连接，健康状态由最近一次解析结果反映；
        // 这里恒为 Healthy，失败会通过 resolve 的错误体现。
        DiscoveryHealth::Healthy
    }
}

/// 把域名编码为 DNS QNAME（长度前缀标签 + 终止 0）。
fn push_qname(out: &mut Vec<u8>, domain: &str) -> Result<(), DiscoveryError> {
    if domain.is_empty() {
        return Err(DiscoveryError::Provider("dns domain is empty".to_string()));
    }
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(DiscoveryError::Provider(format!("dns label too long: {label}")));
        }
        // 注意：label 必须是 ASCII 域名，非 ASCII 由配置侧保证
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// 解析 DNS 应答报文。
///
/// 只提取 A/AAAA/SRV 三类记录；其他类型（CNAME/TXT 等）跳过。
fn parse_response(
    buf: &[u8],
    expected_id: u16,
    kind: DnsQueryKind,
    default_port: u16,
) -> Result<Vec<EndpointConfig>, DiscoveryError> {
    if buf.len() < 12 {
        return Err(DiscoveryError::Provider("dns response too short".to_string()));
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(DiscoveryError::Provider("dns response id mismatch".to_string()));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    // RCODE = flags 低 4 位，非 0 表示解析失败（NXDOMAIN 等）
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(DiscoveryError::Provider(format!("dns rcode {rcode}")));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12usize;
    // 跳过问题区（每个问题 = qname + 4 字节 type/class）
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos
            .checked_add(4)
            .ok_or_else(|| DiscoveryError::Provider("dns offset overflow".to_string()))?;
    }

    let mut out: Vec<EndpointConfig> = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;
        let _class = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;
        let _ttl = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        let rdlen = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        let rdata_end = pos.saturating_add(rdlen);
        if rdata_end > buf.len() {
            break;
        }

        match (kind, rtype) {
            // A 记录：4 字节 IPv4
            (DnsQueryKind::Address, 1) if rdlen == 4 => {
                let ip = std::net::Ipv4Addr::new(
                    buf[pos],
                    buf[pos + 1],
                    buf[pos + 2],
                    buf[pos + 3],
                );
                out.push(EndpointConfig {
                    id: None,
                    host: ip.to_string(),
                    port: default_port,
                    weight: 1,
                    zone: None,
                    // DNS 记录不携带地域信息
                    region: None,
                });
            },
            // AAAA 记录：16 字节 IPv6
            (DnsQueryKind::Address, 28) if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[pos..pos + 16]);
                let ip = std::net::Ipv6Addr::from(octets);
                out.push(EndpointConfig {
                    id: None,
                    host: ip.to_string(),
                    port: default_port,
                    weight: 1,
                    zone: None,
                    // DNS 记录不携带地域信息
                    region: None,
                });
            },
            // SRV 记录：priority(2) + weight(2) + port(2) + target(qname)
            (DnsQueryKind::Srv, 33) if rdlen >= 7 => {
                let weight = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as u32;
                let port = u16::from_be_bytes([buf[pos + 4], buf[pos + 5]]);
                // target 是压缩域名，需要从 pos+6 开始读取
                let target = read_name(buf, pos + 6)?;
                if !target.is_empty() && port != 0 {
                    out.push(EndpointConfig {
                        id: None,
                        host: target,
                        port,
                        // SRV 权重为 0 时按 1 处理，避免端点被负载均衡器完全排除
                        weight: weight.max(1),
                        zone: None,
                        // SRV 记录不携带地域信息
                        region: None,
                    });
                }
            },
            _ => {},
        }

        pos = rdata_end;
    }

    Ok(out)
}

/// 跳过一个（可能压缩的）DNS 名称。
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DiscoveryError> {
    loop {
        if pos >= buf.len() {
            return Err(DiscoveryError::Provider("dns name out of bounds".to_string()));
        }
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        // 压缩指针：0xC0 开头占 2 字节
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// 读取一个（可能压缩的）DNS 名称并还原为字符串。
fn read_name(buf: &[u8], start: usize) -> Result<String, DiscoveryError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0usize;
    loop {
        if pos >= buf.len() {
            return Err(DiscoveryError::Provider("dns name out of bounds".to_string()));
        }
        let len = buf[pos];
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(DiscoveryError::Provider("dns pointer out of bounds".to_string()));
            }
            let offset = u16::from_be_bytes([buf[pos] & 0x3F, buf[pos + 1]]) as usize;
            // 防御性限制跳转次数，避免恶意报文造成死循环
            jumps += 1;
            if jumps > 16 {
                return Err(DiscoveryError::Provider("dns pointer loop".to_string()));
            }
            pos = offset;
            continue;
        }
        let end = pos + 1 + len as usize;
        if end > buf.len() {
            return Err(DiscoveryError::Provider("dns label out of bounds".to_string()));
        }
        let label = std::str::from_utf8(&buf[pos + 1..end])
            .map_err(|_| DiscoveryError::Provider("dns label not utf8".to_string()))?;
        labels.push(label.to_string());
        pos = end;
    }
    Ok(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qname_encoding() {
        let mut out = Vec::new();
        push_qname(&mut out, "a.bc").unwrap_or_default();
        assert_eq!(out, vec![1, b'a', 2, b'b', b'c', 0]);
    }

    #[test]
    fn parse_a_record() {
        // 构造最小应答：header + 问题(example.com) + 1 条 A 记录
        let mut buf = vec![0x00, 0x01, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        let mut q = Vec::new();
        push_qname(&mut q, "example.com").unwrap_or_default();
        buf.extend_from_slice(&q);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        // answer name 用压缩指针指向 offset 12
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&60u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[10, 0, 0, 1]);

        let eps =
            parse_response(&buf, 1, DnsQueryKind::Address, 8080).expect("should parse A record");
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].host, "10.0.0.1");
        assert_eq!(eps[0].port, 8080);
    }
}
