# DNS Observer v0.5.3 — IPv6 TPROXY Root 透明 Socket 验证

- v0.5.2 实测 TPROXY 计数器 pkts=1 但 IPV6_TRANSPARENT socket 不可用。本版将 socket 创建与 UDP 监听移至经 KernelSU `su` 启动的独立 `app_process`，不再由普通 APP 权限创建，也不再使用普通 DatagramSocket 假装可测 TPROXY。
- 先验证 Root + IPV6_TRANSPARENT `::1:15454` 监听，然后发送普通 IPv6 回环包，成功才安装隔离的 TPROXY PREROUTING 跳转，再发送 `::1:15453` 测试包。分别记录 ROOT EUID、实际错误 errno、普通回环与 TPROXY 的接收结果、PREROUTING 和 TPROXY 链命中计数。
- 不创建 / 更改 Android 策略路由、fwmark 规则、系统防火墙链；只对 ::1 测试端口安装最多 20 秒的隔离链。无论异常/正常，尝试调用原有 recover；另保留手动清理按钮和 20 秒 Root 守护程序。
- 使用 Android 自带 `/system/bin/app_process` 从已安装只读 APK 运行 Root 探针；不复制 ELF 到 `/data/local/tmp`，不需要安装 NDK。若当前 KernelSU/SELinux 禁止启动 app_process 或访问 APK，报告精确错误，不能以此否定 TPROXY 内核支持。
- **这是隔离诊断版**：成功也不代表本机 `OUTPUT` 的外网 IPv6 53 流量已实现透明接管；真实接管需另行实现和验证完整流量路径。

---

# DNS Observer v0.5.2 — IPv6 NAT 自动降级 + 隔离 TPROXY 现场验证

- 用户的 OnePlus 12 / Android 16 6.1.141 内核报告 `# CONFIG_IP6_NF_NAT is not set`、`# CONFIG_NF_TABLES is not set`、`CONFIG_NF_TPROXY_IPV6=y`，因此旧版 IPv6 NAT REDIRECT 不可能正常工作。
- 选择 IPv6 重定向后，启动前自动检测 ip6tables NAT；不支持则只开启 IPv4 DNS REDIRECT，并在状态中警告 **IPv6 DNS 未接管**。IPv6 Ping/UDP/TCP DNS 测速不变。
- 新增“验证 IPv6 TPROXY · 限时隔离实验”按钮：只向 `mangle PREROUTING` 加入严格匹配 `-i lo -d ::1/128 --dport 15453` 的 UDP/TCP 临时跳转，使用应用专属 `DO6TST53` 链，测试 `TPROXY --on-ip ::1 --on-port 15454` 在当前 ROM 能否创建以及**仅回环 UDP 报文**是否能被送达本地测试端口。
- **不拦截普通 DNS 53**、不修改 `ip -6 rule`、不写任何 fwmark 策略路由、不触及 `qcom_NWMGR` / `connmark_mangle_OUTPUT` 规则；App finally 清理、20 秒 Root watchdog 自动恢复、显式“一键恢复 IPv6 实验规则”。
- 实验规则安装成功、链计数器命中，都**不代表本机外部 IPv6 DNS 已被接管**；还需要具备 `IPV6_TRANSPARENT` 监听、受控本机 OUTPUT 路由验证和实际 DNS 报文链路验证，这部分未完成，不能宣传为可用 IPv6 DNS 全局接管。
- 请先关闭生产 DNS 接管并保持实验网络可恢复；如果实验恢复按钮报错，先使用 root shell 运行（只删除本实验自有链）：`ip6tables -t mangle -D PREROUTING -i lo -d ::1/128 -p udp --dport 15453 -j DO6TST53` 和 tcp 同理，然后 `ip6tables -t mangle -F DO6TST53; ip6tables -t mangle -X DO6TST53`。
- 编译和模拟规则检查均不能代替 ColorOS 16 实机运行。执行后的现场报告请反馈，尤其“隔离验证是否能插入 TPROXY 目标”和“回环 UDP 是否收到”。

---

# DNS Observer v0.5.1 — ICMP Ping 与 DNS 服务延迟分离

每组（主、从、备）的每个 IPv4/IPv6 地址分别测 ICMP Echo RTT、UDP DNS 查询、TCP DNS 查询。

Ping 不回应不等于 IP 不可达：若 DNS 正常，说明地址可通过 DNS 服务访问；若 Ping 正常而 UDP/TCP DNS 均失败，优先排查 DNS 服务/端口/访问控制；若三项均失败，仍可能是 ICMP 与 DNS 同时被防火墙过滤，不能独断 IP 不通。

本版复用原 upstream_probe 历史表保存 PING (port=0)，无需数据库版本迁移。手动和周期性全量测速会执行 Ping，运行接管时的 60 秒快速健康检查仍只测 UDP/TCP DNS；ICMP Ping 永远不参与 DNS 健康判断或主从备切换。

Android /system/bin/ping 可能受设备权限或网络策略限制，失败时会明确标注原因。本版本只通过 CI 验证，尚无 OnePlus 12 实机结果。

---
# DNS Observer v0.5.0 — 三组上游 / 四通道 DNS 测速

本版本在 v0.4.1 基础上增量扩展，保留 LSPosed Modern API 102 记录、Root 接管、应用名与系统 DNS 配置来源标注。

## 新增

- 3 组上游：主、从、备，分别设置独立域名和独立 UDP/TCP DNS 端口。原 v0.4.1 `secondary_host` 和 `secondary_port` 保留为「备」组，新增 `sub_host` 和 `sub_port` 作为「从」组，不丢旧设置。
- 对每组域名先解析 A/AAAA，然后每个 IP 分别执行真实 **IPv4 UDP、IPv4 TCP、IPv6 UDP、IPv6 TCP** DNS 查询并显示耗时或具体失败原因；使用 `example.com A` 探针并验证响应 ID、QR、RCODE，TCP 测试包含 DNS 长度前缀、建连与响应耗时，非 ICMP Ping。
- 4 通道独立显示最快可用 IP 的延迟及各通道成功/失败数量；单击展开各 IP 完整结果。IPv6 没有可用地址时明确显示「无IPv6地址」，不以失败或未知冒充。
- `upstream_probe` 新 SQLite 表（版本 3），保存 IP、IPv4/IPv6、UDP/TCP、端口、延时、RCODE、失败原因和检测时间；旧版 `records`、`upstream_history` 原有数据保留。逐 IP 记录最近 30 天或最多 12000 条。
- 每组最多测试 12 个 IPv4 和 12 个 IPv6（最多 48 个独立任务）。最多 8 线程并发、20 秒整体检测截止时间，限制无响应 DNS 带来的阻塞。跳过的超额地址数量会在界面中显示，**不是所有 DNS 地址无限制测试**。
- 未接管时手动完整测速，以及 JobScheduler 约 15 分钟周期性探测；运行接管时每分钟快速测部分 IP，每 5 分钟完整扫描。实际定时可受系统省电与网络状态影响。
- 主 → 从 → 备 优先级接管：单次失败会**仅重试本次请求**，3 次主动回退成功才改变全局目标；健康检查连续 2 次判定当前主力不可用时可以故障切换。切回更高优先级需要连续至少 3 次健康成功和切换后至少 5 分钟，降低主备抖动。普通 UDP 请求若 UDP 上游不可达，可尝试 TCP DNS 返回给本地 UDP 请求。
- 开启接管时，如配置纯 IP Bootstrap，才会重解析上游域名；未配置时继续使用已缓存 IP，不允许 Android 系统解析器进入自身重定向回路。主、从、备的缓存 IP 均写入本地设置用于测速。

## 安全限制与注意

- 普通 DNS UDP/TCP (53) 才是 Root 透明接管目标；本版本 **不破解 DoH、DoT、DoQ**，也无法证明每条系统 DNS Hook 请求的实际 DNS 服务器。接管前手动测速不会修改防火墙。
- 三组 DNS 测速中的「可用」指探针查询返回 NOERROR/NXDOMAIN（且响应 ID 匹配）。仅 DNS 响应成功，不代表该 DNS 对所有域名均可用；阻断 `example.com` 的自建 DNS 会被视为探针失败。
- 上游 IP 定时检测可能增加电量与移动流量，全部测速的 IP 数量受限。
- IPv6 测试不要求在 Root 接管中启用 IPv6。若设备没可用 IPv6 网络，IPv6 地址仍显示，但测试可能失败；与无 AAAA 地址区分。
- 单次故障或全局网络断连时可能回滚 Root REDIRECT，不能保证所有 ColorOS/KernelSU 环境的异常均能自动清理。没有开机自动接管。
- Debug APK 签名可能改变；覆盖安装失败前先导出 DNS 日志，卸载旧版会清掉 App 数据。
- **尚未在你的 OnePlus 12 / Android 16 上实机验证 DNS 接管。** GitHub CI 的 Java 单元测试、SQLite 迁移测试及 Android APK 编译不能替代真实 Root 防火墙验证。

## 诊断

页面「主/从/备测速」中逐组展示 IPv4 UDP / TCP 和 IPv6 UDP / TCP，点开每组的 IP 明细。历史中保留最近的逐 IP 测试，聚合历史继续显示域名 IP 变化。对备用服务器出现「全部 UDP 未响应」但 TCP 正常的情况，新版本会明确展示两者不同的状态。

---

# DNS Observer — LSPosed module v0.4.1 (API 102)

**专为系统 DNS 解析记录设计的独立 LSPosed 模块，Java + Android 原生视图，不需要 KernelSU 模块、VPN、网络权限。**

**v0.2.0 重要：此版已迁移到 LSPosed 2.2.1 的 Modern libxposed API 102。** 入口为 `META-INF/xposed/java_init.list`，推荐作用域 `META-INF/xposed/scope.list` 仅为 `system`。不再使用 `assets/xposed_init`、旧版 XposedBridge API 或旧 Manifest 模块元数据。


## 覆盖与边界

系统框架（`system_server`）的 `com.android.server.connectivity.NetdEventListenerService#onDnsEvent` 是唯一的采集入口。此入口在 Android 16 AOSP 中提供 `netId, eventType, returnCode, latencyMs, hostname, ipAddresses, ipAddressesCount, uid`。捕获系统标准 DNS 解析器的查询完成事件，包括通过标准 Java/Native API 触发的解析（并可能包含缓存命中）。

**并不保证所有应用的全部 DNS 流量。** 下列场景不在可靠覆盖范围内：应用自己实现的 DNS-over-HTTPS、DNS-over-QUIC、自定义 TCP/UDP 协议、VPN/代理内部的解析、只连接 IP、不经过系统解析器的逻辑。不能据此断言“某个 App 没进行 DNS 请求”。

**字段不代表的内容：** `eventType` 是 AOSP 的 resolver lookup 事件类型，**不是** A/AAAA RR 类型；`returnCode` 是 resolver 结果码，不是纯 DNS 报文的 RCODE；解析事件通常并不提供上游 DNS 服务器、TTL、CNAME 链、DNS 协议明文包或缓存命中标志。`ipAddresses` 的数量可能被系统截断（界面显示的是捕获子集）。

## 功能

- 域名、IPv4/IPv6 地址、时间、UID、应用包名、netId、事件类型、解析耗时、成功/失败
- 每 3 秒刷新列表；按域名/包名/IP 搜索；成功/失败筛选；长按复制
- 本地 SQLite（默认保留 14 天、最多 20,000 条；列表最多显示最新 120 条；CSV 导出全部保留的记录）
- 记录开关、日志清空、SAF CSV 导出（兼容 Excel UTF-8 BOM）
- 系统 Hook 心跳、队列丢失数、最近 IPC 故障简述
- 不请求 INTERNET / VPN / QUERY_ALL_PACKAGES 权限；不上传日志

## 编译

前提：JDK 17、Android SDK Platform 35 和 Gradle 8.10.2。工程使用 Android Gradle Plugin 8.8.2。

```bash
gradle :app:assembleDebug
```

生成 `app/build/outputs/apk/debug/app-debug.apk`。

如本机没有 Android SDK，可以把这个工程上传到 GitHub 仓库，进入 `Actions` → `Android Debug APK` → `Run workflow`，下载构建出的 `DNSObserver-debug-apk` 工件。请注意私有仓库避免误公开自己的调试信息；当前工程不包含任何真实 DNS 记录。

编译依赖采用 `compileOnly 'io.github.libxposed:api:102.0.0'`（Maven Central），运行时由 LSPosed 提供 API 类。

## 安装

1. 安装构建完成的 APK。
2. LSPosed 2.2.1 中启用 `DNS Observer`，仅选择「系统框架 / System Framework / system」；新版从 `META-INF/xposed/scope.list` 推荐作用域，不再读取旧版 `xposedscope` 元数据。
3. **完整重启手机**（这是系统进程 Hook，重启 App 不足以生效）。
4. 打开 DNS Observer，页面显示「系统 DNS Hook 已连接」后，用浏览器访问从未访问过的域名，查看新记录。
5. 如果始终没有心跳，先检查 LSPosed 模块日志中 `DNSObserver:` 标签；可能是 ColorOS 修改了 `SystemServer` 或 `NetdEventListenerService` 类位置 / 方法签名。**不要反复重启尝试不明 Hook 修补。**

### 安全提醒

该插件 Hook `system_server`，虽然只读且 Hook 回调不访问磁盘，但此类插件仍存在系统不稳定风险。先确认你已掌握 LSPosed/KernelSU 的模块禁用或恢复方式，再在主力机启用。仅用经过本机构建、审计的 APK；不应对网络解析路径写入或替换返回值。

### 诊断

- 在框架日志或 logcat 中搜索 `DNSObserver:`，首先应看到 `module loaded` 和 `system server starting`；然后检查 `lifecycle hooks installed` 与 `DNS event hooks installed`。
- 页面显示心跳表示已加载系统 Hook 且后台进程与数据库 IPC 可达，**不表示所有 DNS 方式都已被监控**。
- 页面心跳正常但无记录：可能尚未发生标准系统解析，或当前设备 DNS 模块没有通知该回调。先用多个常规应用进行验证。
- 保存数据只有本机 App 私有目录可见。导出的 CSV 位于用户在 Android 文件选择器选定的位置。
- 暂停后系统 Hook 仍工作，但存储端丢弃新的记录。

## 架构与性能

```text
AOSP DnsResolver / netd  -> NetdEventListenerService.onDnsEvent (system_server)
                        -> only copy fields + bounded ArrayDeque (max 1200)
                        -> HandlerThread batch up to 40 -> ContentResolver.call (system UID)
                        -> SecureProvider (UID check) -> SQLite -> Android UI / CSV
```

不会修改原始 DNS 返回值，不会抓包、不启动本地 DNS 服务器，也不会和 Mihomo/SmartDNS/AdGuardHome 争夺 53 端口。

## v0.2.0 / Modern API 102 诊断

- 若 LSPosed 模块日志仍无 `DNSObserver:`，优先查看框架日志，并通过 `adb logcat -d -s DNSObserver:I` 判断是否有应用注入日志；两者都没有时应检查模块启用、作用域和系统进程注入状态。
- `module loaded` 表示 libxposed modern 入口加载成功。
- `system server starting` 表示进入系统服务启动回调。
- `lifecycle hooks installed` 表示已安装系统 Context 获取点；`collector started` 表示后台心跳线程启动。
- `DNS event hooks installed` 表示 DNS 事件 Hook 安装成功，**并不保证所有 DNS 途径都被捕获**。
- `IPC retry` 表示从 system_server 到 App Provider 的心跳/数据库通道失败。
- **系统框架 Hook 有开机风险。** 请确保可在 KernelSU/LSPosed 中禁用模块后再安装测试；不要盲目反复重启。
- **GitHub Actions debug APK 的签名证书可能随构建环境改变**，覆盖安装如提示签名冲突，应先导出旧日志再卸载旧版本安装新版；会清除原 App 的本地数据。

## 当前验证状态

完成源代码静态检查、XML 解析检查以及独立 `TextPolicy` JVM 回归测试。当前执行环境没有 Android SDK / Gradle，**GitHub Actions 已完成 APK 编译，但尚未完成 ColorOS 16 实机运行验证**。发布的是开发验证版源码，不应视作已实测稳定版本。

## v0.3.0：可选 Root DNS 接管（实验性）

**旧版 LSPosed API 102 DNS 监控代码保持不变**。新增独立的 `DnsControlActivity`、`DnsForwardService`、`DnsBootstrap`、`DnsPacket`、`DnsRootRules` 和 `assets/dns-root.sh`。

1. 首次启动不会修改任何网络规则；仅在「DNS 接管设置」内点击「启动 DNS 接管」后执行。
2. 填写上游纯域名（例如 `dns.example.net`，不要包含协议/端口），端口默认 31017；可选备用 Bootstrap **纯 IP** 服务器，留空则只使用系统 DNS。
3. 点击「检测上游 UDP/TCP DNS」；会分别进行真实 DNS 报文探测，不执行 Root 命令。
4. 启动时先解析上游域名，再进行 UDP DNS 探测，然后绑定 `127.0.0.1:15353`（按需还绑定 `::1:15353`），最后安装 Root NAT 规则。失败时自动调用专属规则清理。
5. NAT 仅处理本机 `OUTPUT` 中的普通 UDP/TCP 53，使用专属 `DOBSR53` 链，并从转发中排除 App 自身 UID、IPv4/IPv6 回环地址；不修改系统 DNS 属性、不覆盖其它规则、不改系统分区。
6. 接管前清理自身可能残留的规则，再使用系统 DNS 预解析上游域名；失败时可经备用纯 IP Bootstrap 查询 A/AAAA。**接管启用后绝不再调用系统 DNS 解析上游域名**：Android dnsresolver 可能以非 App UID 发包。若配置纯 IP Bootstrap，约每 5 分钟通过 App 的直接 UDP Socket 更新上游 IP；未配置时保持预解析 IP，失效后安全回滚。这里不是精确按 TTL 更新。
7. 持续上游错误后尝试恢复原系统 DNS。另有 Root shell watchdog 检查主 App 进程及工作规则，尝试在进程死亡后清理专属链。**无法保证所有设备都能自动回滚**。
8. 页面可手动关闭、紧急清理规则。不开机自启，无常驻 KernelSU 模块；关掉接管不影响原有 DNS 监控。

### 真实设备上的限制与风险

- 这是 **普通 DNS UDP/TCP 53** 透明转发，不是 DoH/DoT/DoQ 强制破解。浏览器内置 DoH、Android 私人 DNS、VPN/TUN 内部解析、直接连 IP 的场景可能绕过。
- IPv6 DNS 重定向需要设备具有可用的 ip6tables NAT/REDIRECT。**默认不勾选 IPv6**，建议先验证 IPv4 接管，再打开 IPv6。
- App 进程可能被系统终止，Root 和防火墙行为因 ROM/KernelSU/Mihomo 而异。请先确认有 Root 恢复途径，不要第一次使用就启用开机接管。对端是公网时普通 DNS 不加密。
- 备用 Bootstrap 纯 IP DNS 仅用于上游域名引导，不负责所有普通 DNS；上游转发可能需要 TCP，前台服务通知在系统限制下可能受影响。
- 当前仅编译检查和 JVM 核心测试，不代表已经在 ColorOS 16 上验证 Root NAT 实际生效。启用后应对照远端服务器日志和实际客户端解析检查。
- 此版本增加 `INTERNET` 和 Android `specialUse` 前台服务权限，均用于本地代理/原始 DNS 连接，不上传监控数据库。
- GitHub Actions 默认 debug 签名可能与先前安装的 APK 不一致；覆盖更新失败时先导出 DNS Observer CSV，再卸载旧版本，会清空本地记录。

### Root 恢复（发生网络异常时）

可在 App「DNS 接管设置」点击「紧急清理 Root 重定向规则」。如 App 无法打开，可在具备 Root 权限的 shell 执行下面的命令（只操作模块链）：

```sh
su -c 'iptables -t nat -D OUTPUT -p udp --dport 53 -j DOBSR53'
su -c 'iptables -t nat -D OUTPUT -p tcp --dport 53 -j DOBSR53'
su -c 'iptables -t nat -F DOBSR53; iptables -t nat -X DOBSR53'
# 如果曾开启 IPv6，请同样以 ip6tables 替换 iptables 执行。
```


## v0.4.1 功能和准确性说明

- 原有全局 LSPosed 监听保持不变；日志可筛选成功/失败，折叠多 IP，显示应用名/包名/解析结果/解析类型和 DNS 服务器地址。
- **协议证据限制**：系统的 `NetdEventListenerService.onDnsEvent` 没有 DoH/DoT 流量协议字段；记录中显示的是系统 LinkProperties 的默认网络私人 DNS / DNS 列表快照，或接管器配置的上游，明确标注为配置快照，不是按次真实网络抓包。应用私有 DoH 可能根本不产生系统事件，绝不误标为 DoH。
- 主/备用上游独立填写域名和端口。Bootstrap 纯 IP DNS 用于域名解析，是另外一种设置。上游通信暂仅 UDP/TCP（不是 DoH/DoT）。主服务器失败时尝试备用，并记录当前所用的角色/IP；在主服务器恢复后恢复主服务器优先。
- 接管开启后每 60 秒探测主备延时，每 5 分钟在提供 Bootstrap 纯 IP 时通过独立 Socket 重新解析并更新主备 IP；不提供纯 IP Bootstrap 则只检查缓存的 IP，不使用系统 DNS 以免透明接管循环。
- 在未接管时使用 Android JobScheduler 每约 15 分钟执行健康检查及 DNS 域名刷新（Android 的 Doze 可能延迟）。进入 DNS 接管配置页后启动此系统调度；打开配置页还能立即手动检测。历史保存最近 30 天/1000 项，包括失败原因/IP/延时。
- 数据库从 schema 1 自动迁移到 2，保留旧日志，旧日志新字段显示“未知”。
- **Root 接管有风险，首次应先检测并手动开启，不启用开机自动接管。** 如果失败应使用关闭/紧急恢复，并验证手机网络恢复。

## v0.4.1: Android 16 诊断修复

- 修复 DNS 接管页打开时可能出现的 `SecurityException`：`JobScheduler.setRequiredNetworkType(ANY)` 在 Android 14+ 要求 `ACCESS_NETWORK_STATE`；添加清单权限，并在调度被 ROM 拒绝时捕获异常，保障页面可用。
- 使用 App 进程的 `ConnectivityManager.getLinkProperties()` 再次解析每条记录的 `netId` 对应网络（无法定位时仅尝试默认网络），并记录配置来源。保留 LSPosed 采集逻辑。
- 对无法读取的应用名称，依次尝试 UID 对应包名，历史记录优先显示已保存包名而非“未知应用”。
- Android 的 onDnsEvent 不包含实际 DNS 上游地址和 DoH/DoT 报文字段；显示的 DNS 服务器是网络配置快照或 Root 接管配置，而非已抓到单次包的真实目标。
- 历史记录未保存的字段无法倒推过去的真实 DNS 服务器/协议，不对旧数据伪造补录。升级后新记录将尝试保存网络配置和应用名称。
- 即使接管页面打开成功，Root NAT 接管也尚未在 OnePlus 12 / ColorOS 16 上实机验证；建议先通过“检测上游”再选择手动启用。

### v0.4.1 应用名称兼容补充

`QUERY_ALL_PACKAGES` 仅用于在本机为 DNS 日志中的任意 UID/包名查询可读应用标签，以及补录既有日志中空白的 appName。由于 Android 11+ 应用可见性限制，未授权全面包可见性时读取任意应用标签可能失败。该权限可使本 App 看到所有安装包信息，属于敏感数据访问；工程不上传应用清单，也不主动枚举整机安装包，只按已捕获的 DNS 记录逐项查询。若计划发布至 Google Play，需另行核对平台的敏感权限申报和适用政策。
