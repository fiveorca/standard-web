//! CIDR / IP 网段匹配器。
//!
//! 用于 IP Allowlist / IP Denylist 两种策略。
//!
//! # 匹配语义
//!   - 配置项可以是 CIDR（`10.0.0.0/8`、`::1/128`）
//!   - 也可以是单个 IP（`192.168.1.5`），等价于前缀长度 32/128 的网段
//!   - 匹配一律基于 `IpAddr` 并且**区分 IPv4/IPv6**：
//!     `::ffff:10.0.0.1` 不会命中 `10.0.0.0/8`，避免 IPv6 映射地址绕过 IP 名单
//!
//! # 为什么启动期编译
//! 每次请求都解析 CIDR 字符串会带来不必要的分配与字符串扫描。
//! 启动期一次性解析为 `IpNet` 列表，请求路径上只做三两比较。

use std::net::IpAddr;

use ipnet::IpNet;

/// 预编译的网段匹配器。
#[derive(Debug, Clone)]
pub struct CidrMatcher {
    /// 已解析的网段列表（启动期构建，运行期只读）
    nets: Vec<IpNet>,
}

impl CidrMatcher {
    /// 从配置字符串编译匹配器。
    ///
    /// 参数：
    /// - `entries`：CIDR 或单个 IP 的字符串列表（来自 YAML 配置）
    ///
    /// 返回：
    /// - `Ok(matcher)`：全部解析成功
    /// - `Err(reason)`：任一配置项非法（**整条策略拒绝加载**，不做部分生效）
    ///
    /// 说明：配置 validator 已提前校验过格式；这里再校验一次属于
    /// "防御式编程"——策略编译不依赖调用方一定先跑了校验。
    pub fn compile(entries: &[String]) -> Result<Self, String> {
        // 空列表没有语义：allowlist 为空会拒绝全部流量、denylist 为空形同虚设，
        // 两者都属于配置错误，必须在启动期拒绝而不是静默生效
        if entries.is_empty() {
            return Err("cidrs must not be empty".into());
        }

        let mut nets = Vec::with_capacity(entries.len());
        for (idx, raw) in entries.iter().enumerate() {
            // 去首尾空白，容忍 YAML 中的缩进残留
            let text = raw.trim();
            if text.is_empty() {
                return Err(format!("cidrs[{idx}] is empty"));
            }

            // 先按 CIDR 解析；失败再按单个 IP 解析
            let net = match text.parse::<IpNet>() {
                Ok(net) => net,
                Err(cidr_err) => match text.parse::<IpAddr>() {
                    // `IpNet::from(IpAddr)`：IPv4 → /32，IPv6 → /128
                    Ok(ip) => IpNet::from(ip),
                    Err(_) => {
                        return Err(format!(
                            "cidrs[{idx}] '{text}' is neither CIDR nor IP ({cidr_err})"
                        ));
                    },
                },
            };
            nets.push(net);
        }

        Ok(Self { nets })
    }

    /// 判断给定 IP 是否命中任一段。
    ///
    /// 参数：
    /// - `ip`：客户端地址（来自 `SocketAddr::ip()`）
    pub fn contains(&self, ip: IpAddr) -> bool {
        // `IpNet::contains` 内部按地址族比较，不会把 IPv6 映射地址误判进 IPv4 段
        self.nets.iter().any(|net| net.contains(&ip))
    }

    /// 网段数量（启动自检与日志用）。
    pub fn len(&self) -> usize {
        self.nets.len()
    }

    /// 是否为空（构造时已保证非空，保留该方法是 clippy 的配套约定）。
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助：构造字符串列表
    fn entries(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// CIDR 与单 IP 混用都能正确匹配
    #[test]
    fn matches_cidr_and_single_ip() {
        let matcher = CidrMatcher::compile(&entries(&["10.0.0.0/8", "192.168.1.5"]))
            .expect("valid cidrs");
        assert!(matcher.contains("10.1.2.3".parse().expect("ipv4")));
        assert!(matcher.contains("192.168.1.5".parse().expect("ipv4")));
        assert!(!matcher.contains("192.168.1.6".parse().expect("ipv4")));
        assert_eq!(matcher.len(), 2);
    }

    /// IPv6 网段匹配，且 IPv4 地址不会误命中 IPv6 段
    #[test]
    fn ipv6_matching_is_family_aware() {
        let matcher = CidrMatcher::compile(&entries(&["::1/128", "fe80::/10"]))
            .expect("valid ipv6 cidrs");
        assert!(matcher.contains("::1".parse().expect("ipv6")));
        assert!(matcher.contains("fe80::abcd".parse().expect("ipv6")));
        // IPv4 地址与 IPv6 段属于不同地址族
        assert!(!matcher.contains("10.0.0.1".parse().expect("ipv4")));
    }

    /// 非法配置必须整体拒绝：空白、空列表、格式错误
    #[test]
    fn invalid_entries_are_rejected() {
        assert!(CidrMatcher::compile(&[]).is_err());
        assert!(CidrMatcher::compile(&entries(&["   "])).is_err());
        assert!(CidrMatcher::compile(&entries(&["10.0.0.999"])).is_err());
        assert!(CidrMatcher::compile(&entries(&["10.0.0.0/33"])).is_err());
    }
}
