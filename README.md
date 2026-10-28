# DNS Observer v0.6.2-beta4 — 统一 IPv4 / IPv6 DNS 接管控制

- IPv4 NAT 与 IPv6 TPROXY **独立复选框**。至少选一项启动。依然只处理 UDP/TCP 53；不覆盖 DoH/DoT/DoQ；IPv6 Root UID 0 不劫持。
- 统一“关闭接管”不参考勾选，发送停止 IPv4 和 IPv6 服务请求，清理 DOBSR53 / DO6G061 / DO6TST55 自有链及相应标记、策略路由、局部规则；不 flush 系统表、不删外部规则。返回残留核查结果。
- **取消自动定时关闭**：正式 IPv6 不再 145 秒退出，也不再 180 秒看门狗定时回滚。异常时 Root 代理关闭仍执行安全清理，避免断网；这不是周期性超时恢复。原 UID 隔离诊断仍为限时测试，但不在主页面上。
- 新增检测系统覆盖：前台服务每约 15 秒读取 IPv4 NAT 和 IPv6 TPROXY 自有规则状态，记录一次状态异常事件到独立事件日志。若开启“被系统覆盖后自动重新接管”，则仅在用户要求接管且没有手动关闭时尝试修复或重启 IPv6 Root 代理；默认关闭。
- 新增开机自启开关：在 Android BOOT_COMPLETED 后，如果“开机自动启动”及“上次仍要求接管”均为 true，则尝试恢复选择的 IPv4/IPv6 代理。手动关闭将清除“要求接管”的状态，所以之后的开机不会偷偷重新启用。
- 主/从/备**仅使用指定 Bootstrap DNS 纯 IP**解析域名：删除 Android 系统 `InetAddress.getAllByName` 优先路径。用户直接配置数字 IP 则直接使用，不触发域名查询；Bootstrap 为空且需解析域名时拒绝启动。
- UI 清理重复的历史实验入口，使用深色圆角按钮、IPv4/IPv6 开关与独立垂直滚动日志框：接管状态、覆盖检测、测速明细、IPv6 Root 日志、测速历史。每一类日志都有复制，关键日志可清空。

## 重要边界

beta4 编译通过不等于已在 OnePlus 12 实机验证持续接管及开机自启。务必先关闭系统 Private DNS 与冲突的第三方透明 DNS 规则，在非关键网络环境逐步检查 IPv4-only、IPv6-only 和双协议启动、手动关闭（查看残留核对），然后再开启自动修复与开机自启。Android 后台启动策略和 ROM Root 权限可能限制开机行为。本版不承诺接管 Android 全部 DNS Resolver UID 及加密 DNS。

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
