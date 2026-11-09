//! IP 黑白名单 / CIDR 访问控制。

use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::model::IpFilterConfig;

/// 编译后的 IP 过滤器。
#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl IpFilter {
    pub fn new(config: &IpFilterConfig) -> Result<Self, String> {
        Ok(Self {
            allow: parse_cidrs(&config.allow)?,
            deny: parse_cidrs(&config.deny)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// 黑名单优先；白名单非空时必须命中。
    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|net| net.contains(&ip))
    }

    pub fn allow_len(&self) -> usize {
        self.allow.len()
    }

    pub fn deny_len(&self) -> usize {
        self.deny.len()
    }
}

fn parse_cidrs(values: &[String]) -> Result<Vec<IpNet>, String> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|e| format!("invalid IP / CIDR `{value}`: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_wins_over_allow() {
        let filter = IpFilter::new(&IpFilterConfig {
            allow: vec!["10.0.0.0/8".into()],
            deny: vec!["10.1.0.0/16".into()],
        })
        .unwrap();
        assert!(filter.allows("10.2.3.4".parse().unwrap()));
        assert!(!filter.allows("10.1.2.3".parse().unwrap()));
        assert!(!filter.allows("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr() {
        let filter = IpFilter::new(&IpFilterConfig {
            allow: vec!["2001:db8::/32".into()],
            deny: vec![],
        })
        .unwrap();
        assert!(filter.allows("2001:db8::1".parse().unwrap()));
        assert!(!filter.allows("2001:db9::1".parse().unwrap()));
    }
}
