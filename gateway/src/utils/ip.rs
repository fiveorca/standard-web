//! 客户端真实 IP 解析。
//!
//! 只有在直连对端属于可信代理时，才会采信 `X-Forwarded-For` /
//! `Forwarded` 头，避免客户端伪造这些头绕过 IP 访问控制。

use std::net::IpAddr;

use http::HeaderMap;
use ipnet::IpNet;

/// 客户端 IP 解析器。
#[derive(Debug, Clone, Default)]
pub struct ClientIpResolver {
    trusted: Vec<IpNet>,
}

impl ClientIpResolver {
    /// 根据 CIDR 列表构造解析器。
    pub fn new(cidrs: &[String]) -> Result<Self, String> {
        let mut trusted = Vec::with_capacity(cidrs.len());
        for raw in cidrs {
            let net: IpNet = raw
                .parse()
                .map_err(|e| format!("invalid trusted proxy CIDR `{raw}`: {e}"))?;
            trusted.push(net);
        }
        Ok(Self { trusted })
    }

    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }

    /// 判断 IP 是否属于可信代理。
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// 解析真实客户端 IP。
    ///
    /// 规则：从右向左遍历代理链，跳过可信代理，第一个不可信的地址即为客户端地址。
    pub fn resolve(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let peer = peer?;
        if !self.is_trusted(peer) {
            // 直连对端不可信：任何转发头都不可采信。
            return Some(peer);
        }

        let mut chain: Vec<IpAddr> = Vec::new();
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            for part in xff.split(',') {
                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                    chain.push(ip);
                }
            }
        }
        if chain.is_empty() {
            if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
                for part in forwarded.split(',') {
                    for kv in part.split(';') {
                        let kv = kv.trim();
                        if let Some(rest) = kv.strip_prefix("for=") {
                            let value = rest.trim_matches('"');
                            let value = value.trim_start_matches('[');
                            let value = value.split(']').next().unwrap_or(value);
                            let value = value.rsplit(':').next().unwrap_or(value);
                            if let Ok(ip) = value.parse::<IpAddr>() {
                                chain.push(ip);
                            }
                        }
                    }
                }
            }
        }

        // 从最右侧（最靠近网关）开始寻找第一个不可信地址。
        for ip in chain.iter().rev() {
            if !self.is_trusted(*ip) {
                return Some(*ip);
            }
        }
        Some(peer)
    }

    /// 生成用于转发链的完整地址列表（最右侧为最新一跳）。
    pub fn forwarded_chain(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Vec<IpAddr> {
        let mut result = Vec::new();
        if let Some(peer) = peer {
            if self.is_trusted(peer) {
                if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                    for part in xff.split(',') {
                        if let Ok(ip) = part.trim().parse::<IpAddr>() {
                            if self.is_trusted(ip) {
                                result.push(ip);
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            result.push(peer);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());
        headers
    }

    #[test]
    fn ignores_xff_from_untrusted_peer() {
        let resolver = ClientIpResolver::new(&["10.0.0.0/8".to_string()]).unwrap();
        let peer = Some("203.0.113.9".parse().unwrap());
        let headers = headers_with_xff("1.2.3.4");
        assert_eq!(resolver.resolve(peer, &headers), peer);
    }

    #[test]
    fn resolves_chain_from_trusted_peer() {
        let resolver = ClientIpResolver::new(&["10.0.0.0/8".to_string()]).unwrap();
        let peer = Some("10.0.0.5".parse().unwrap());
        let headers = headers_with_xff("9.9.9.9, 198.51.100.7");
        assert_eq!(
            resolver.resolve(peer, &headers),
            Some("198.51.100.7".parse().unwrap())
        );
    }

    #[test]
    fn skips_trusted_hops() {
        let resolver = ClientIpResolver::new(&["10.0.0.0/8".to_string()]).unwrap();
        let peer = Some("10.0.0.5".parse().unwrap());
        let headers = headers_with_xff("198.51.100.7, 10.1.1.1");
        assert_eq!(
            resolver.resolve(peer, &headers),
            Some("198.51.100.7".parse().unwrap())
        );
    }

    #[test]
    fn no_trusted_proxies_means_direct_peer_wins() {
        let resolver = ClientIpResolver::default();
        let peer = Some("192.0.2.1".parse().unwrap());
        let headers = headers_with_xff("1.2.3.4");
        assert_eq!(resolver.resolve(peer, &headers), peer);
    }
}
