# DNS Observer v0.6.1-beta3 — IPv6 DNS53 全局试用（必须手动启用）

基于 OnePlus 12 Android 16 / KernelSU 的实验反馈：v0.5.9 DNS53 UDP/TCP 真实上游转发闭环成功，v0.6.0-beta2 连续 16 轮通过并在手动停止后 `VERIFY_CLEAN`。本版进一步实现**普通非 Root UID 的 IPv6 单播 UDP/TCP 53 接管**，不是默认自动开启，也不包含 DoH/DoT/DoQ。

## 激活顺序（降低故障风险）

1. 用户明确点击「开启 IPv6 全局 DNS53」，并确认网络中断风险；未点击时不写任何 IPv6 全局规则。
2. 在任何 mangle/路由修改前，解析并预检已保存的主/从/备上游 IP，确保 UDP/TCP 实际 DNS 都可用。
3. 创建独立 Root 代理（`DnsIpv6GlobalDaemon`，UDP/TCP `::1:15456`，4 workers / 32 queue，145 秒硬期限）。UDP 使用 Android `Os.recvmsg` + `IPV6_RECVPKTINFO` 获取每个包原始 IPv6 目标，响应专用临时透明 Socket 绑定 **原始目标 IPv6:53**；TCP 使用 `Os.getsockname(accepted)` 检查原始目标 IP:53 并在透明连接回传。
4. 安装 `DO6G061` 独立链、mark `0x40000000/0x40000000`、route table `19754`、priority `15010`；一开始 OUTPUT **仅匹配 DNS Observer 自身 UID**。对 `2001:db8:ffff::53` 和 `2001:db8:ffff::54` 两个不同 IPv6 目标分别发送 UDP、TCP DNS 查询，验证真实上游响应和原始目标源地址。任何失败直接终止，不扩大规则，并核查恢复。
5. 四项自检通过后才调用 `promote`，把 OUTPUT 限制扩到**非 UID 0** 本机进程的 IPv6 全球单播（`2000::/3`）与 ULA（`fc00::/7`）53 端口；仍只拦截本机 OUTPUT，不改 LAN 转发，不影响原有 IPv4 `dns-root.sh`。再进行 2 项回归查询；失败立刻撤销。
6. 145 秒 Root 服务期限、独立 180 秒看门狗；Root 服务退出则尝试自动恢复。提供单独停止/恢复按钮、独立日志及清空按钮。所有清理均要求 `VERIFY_CLEAN`，不调用 `-F OUTPUT`、不碰其他服务的路由表。

## 特别注意

- **不能保证覆盖 Android DNS Resolver 及全部应用**：UID 0 故意排除，防止 Root 上游转发递归；如果某 ROM 的 DNSResolver 以 UID 0 查询，这部分不会被接管。用户态 App 的 DoH/DoT/DoQ 不属于 UDP/TCP 53。
- **不能保证网络不中断**：`recvmsg` 的 IPv6 PKTINFO 是否为真实目的地址、TCP `getsockname` 的表现必须通过这台设备的双文档目标自检确定。即使通过也必须先观察实际应用行为；切勿在无 Root 回滚能力时开启。
- 自检期/启用期的 IPv6 DNS53 请求可能被重定向。若代理异常退出或上游全部失败，尽力自动回滚；独立看门狗是最终后备，**并非毫无条件保证一定恢复**。
- UDP per-query reply socket 新建绑定有并发开销，真实多客户端压力尚未实测。适合本次限时试用，不应当作无人值守长期全局代理。
- 旧 beta2 UID 隔离试运行保留在折叠的“高级诊断”，以便比较与恢复；主/从/备配置、IPv4 REDIRECT 与 LSPosed 监控不变。

### 需要实机返回的日志

主要看 `自检 UDP/TCP 2001:db8:ffff::53`、`...::54`、`PROMOTED`、`UDP_RECV_ERROR`、`TCP_QUERY_ERROR`、`VERIFY_CLEAN`。只有 `PROMOTED` 后才开始实际全局非 Root UID 的有限期接管。
