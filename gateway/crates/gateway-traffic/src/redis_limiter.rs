//! Redis 分布式限流器（Phase 6）。
//!
//! # 为什么自实现 RESP 客户端
//!
//! 只需要 `EVAL` + `SELECT` 两条命令，引入完整 `redis` crate 会把异步
//! 连接池、集群拓扑等能力带进数据面，超出需求。这里实现最小 RESP
//! 编码/解码，保持 `gateway-traffic` 依赖面干净。
//!
//! # 算法
//!
//! Redis 后端固定使用**固定窗口**：
//!
//! ```lua
//! local c = redis.call('INCR', KEYS[1])
//! if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
//! return c
//! ```
//!
//! `INCR` 与首次 `EXPIRE` 在同一个 Lua 脚本中执行，保证多实例并发下
//! 计数与过期时间一致（原子性由 Redis 单线程模型保证）。
//!
//! # 连接管理
//!
//! 每个策略持有一个 `Mutex<Option<BufStream<TcpStream>>>`，命令串行执行。
//! IO 失败会丢弃连接，下次请求自动重连——不引入后台重连任务。

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// 单次命令超时：必须远小于插件 100ms 上限，避免拖慢请求路径。
const COMMAND_TIMEOUT: Duration = Duration::from_millis(50);

/// 限流判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitOutcome {
    /// 是否放行
    pub allowed: bool,
    /// 建议的 Retry-After（秒）
    pub retry_after_secs: Option<u64>,
}

/// Redis 固定窗口限流器。
pub struct RedisLimiter {
    /// 连接地址（redis://host:port/db）
    url: String,
    /// 每个窗口允许的请求数
    rate: u64,
    /// 窗口长度（秒）
    window_secs: u64,
    /// 复用的连接（懒建立）
    conn: Mutex<Option<BufStream<TcpStream>>>,
}

impl RedisLimiter {
    /// 构造限流器。
    ///
    /// `rate` 必须大于 0，`window_secs` 必须大于 0（编译期已校验）。
    pub fn new(url: impl Into<String>, rate: u64, window_secs: u64) -> Self {
        Self {
            url: url.into(),
            rate,
            window_secs: window_secs.max(1),
            conn: Mutex::new(None),
        }
    }

    /// 判断本次请求是否放行。
    pub async fn try_acquire(&self, key: &str) -> Result<RateLimitOutcome, String> {
        // 固定窗口编号：epoch / window_secs
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window_index = now / self.window_secs;
        let redis_key = format!("gw:rl:{}:{}:{}", self.rate, key, window_index);

        let script = "local c = redis.call('INCR', KEYS[1])\n\
                      if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end\n\
                      return c";
        let window_str = self.window_secs.to_string();

        let count = tokio::time::timeout(
            COMMAND_TIMEOUT,
            self.execute(&["EVAL", script, "1", &redis_key, &window_str]),
        )
        .await
        .map_err(|_| "redis command timed out".to_string())??;

        let allowed = (count as u64) <= self.rate;
        // 距离窗口结束还剩多少秒
        let retry_after_secs = if allowed {
            None
        } else {
            // 从当前窗口起点算剩余时间
            let window_end = (window_index + 1) * self.window_secs;
            Some(window_end.saturating_sub(now).max(1))
        };

        Ok(RateLimitOutcome {
            allowed,
            retry_after_secs,
        })
    }

    /// 递增一个任意命名空间的固定窗口计数器，返回 `(当前计数, 窗口编号)`。
    ///
    /// 与 [`try_acquire`](Self::try_acquire) 使用同样的 `INCR + EXPIRE`
    /// 原子脚本，但把 `rate` 从 key 前缀里去掉，改用 `namespace`，
    /// 这样配额插件可以复用同一连接与窗口语义，同时拿到精确计数
    /// （用于返回剩余配额 Header）。
    pub async fn incr_window(&self, namespace: &str, key: &str) -> Result<(u64, u64), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window_index = now / self.window_secs;
        let redis_key = format!("gw:{namespace}:{key}:{window_index}");

        let script = "local c = redis.call('INCR', KEYS[1])\n\
                      if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end\n\
                      return c";
        let window_str = self.window_secs.to_string();

        let count = tokio::time::timeout(
            COMMAND_TIMEOUT,
            self.execute(&["EVAL", script, "1", &redis_key, &window_str]),
        )
        .await
        .map_err(|_| "redis command timed out".to_string())??;

        Ok((count.max(0) as u64, window_index))
    }

    /// 执行一条命令，返回整数应答。
    ///
    /// 连接失败/协议错误时丢弃连接（下次重连）并返回错误字符串。
    async fn execute(&self, args: &[&str]) -> Result<i64, String> {
        let mut guard = self.conn.lock().await;
        // 懒建立连接
        if guard.is_none() {
            match connect(&self.url).await {
                Ok(conn) => *guard = Some(conn),
                Err(err) => return Err(err),
            }
        }

        let Some(conn) = guard.as_mut() else {
            return Err("redis connection unavailable".to_string());
        };

        let result = async {
            write_command(conn, args)
                .await
                .map_err(|e| format!("redis write failed: {e}"))?;
            read_integer(conn).await.map_err(|e| format!("redis read failed: {e}"))
        }
        .await;

        if result.is_err() {
            // IO/协议错误：连接状态不可信，丢弃后重连
            *guard = None;
        }
        result
    }
}

impl std::fmt::Debug for RedisLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisLimiter")
            .field("url", &self.url)
            .field("rate", &self.rate)
            .field("window_secs", &self.window_secs)
            .finish()
    }
}

/// 解析 `redis://host:port[/db]` 并建立连接。
async fn connect(url: &str) -> Result<BufStream<TcpStream>, String> {
    let (host, port, db) = parse_redis_url(url)?;
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("redis connect {host}:{port} failed: {e}"))?;
    let mut conn = BufStream::new(stream);

    if db != 0 {
        let db_str = db.to_string();
        write_command(&mut conn, &["SELECT", &db_str])
            .await
            .map_err(|e| format!("redis select failed: {e}"))?;
        read_integer(&mut conn).await.map_err(|e| format!("redis select failed: {e}"))?;
    }

    Ok(conn)
}

/// 解析 Redis URL。
fn parse_redis_url(url: &str) -> Result<(String, u16, u32), String> {
    let rest = url
        .strip_prefix("redis://")
        .ok_or_else(|| format!("unsupported redis url (only redis:// is supported): {url}"))?;
    // 去掉可能的认证信息（user:pass@）——本实现不发送 AUTH
    let rest = match rest.split_once('@') {
        Some((_, after)) => after,
        None => rest,
    };
    let (host_port, db_part) = match rest.split_once('/') {
        Some((hp, db)) => (hp, db),
        None => (rest, ""),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|e| format!("invalid redis port: {e}"))?),
        None => (host_port, 6379),
    };
    if host.is_empty() {
        return Err("redis host must not be empty".to_string());
    }
    let db = if db_part.is_empty() {
        0
    } else {
        db_part.parse::<u32>().map_err(|e| format!("invalid redis db index: {e}"))?
    };
    Ok((host.to_string(), port, db))
}

/// 按 RESP 协议写入命令（Inline 也能被 Redis 接受，但统一用数组协议更稳）。
async fn write_command<S>(conn: &mut S, args: &[&str]) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = String::with_capacity(32 + args.len() * 16);
    buf.push_str(&format!("*{}\r\n", args.len()));
    for arg in args {
        buf.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }
    conn.write_all(buf.as_bytes()).await?;
    conn.flush().await
}

/// 读取整数应答（`:` 前缀）。
async fn read_integer<S>(conn: &mut S) -> Result<i64, String>
where
    S: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    conn.read_line(&mut line)
        .await
        .map_err(|e| format!("redis read line failed: {e}"))?;
    let line = line.trim_end_matches(['\r', '\n']);
    if line.starts_with('-') {
        return Err(format!("redis error: {line}"));
    }
    line.strip_prefix(':')
        .ok_or_else(|| format!("unexpected redis reply: {line}"))?
        .parse::<i64>()
        .map_err(|e| format!("invalid redis integer reply: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redis_url() {
        let (host, port, db) = parse_redis_url("redis://127.0.0.1:6379/2").expect("parse");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 6379);
        assert_eq!(db, 2);

        let (host, port, db) = parse_redis_url("redis://cache").expect("parse");
        assert_eq!(host, "cache");
        assert_eq!(port, 6379);
        assert_eq!(db, 0);
    }

    #[test]
    fn rejects_non_redis_scheme() {
        assert!(parse_redis_url("http://localhost").is_err());
    }
}
