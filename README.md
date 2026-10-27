# DNS Observer — LSPosed module v0.1.0

**专为系统 DNS 解析记录设计的独立 LSPosed 模块，Java + Android 原生视图，不需要 KernelSU 模块、VPN、网络权限。**

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

如本机没有 Android SDK，可以把这个工程解压上传到 **自己私有的 GitHub 仓库**，进入 `Actions` → `Android Debug APK` → `Run workflow`，下载构建出的 `DNSObserver-debug-apk` 工件。请注意私有仓库避免误公开自己的调试信息；当前工程不包含任何真实 DNS 记录。

`app/libs/xposed-api-compile-stubs.jar` 只是为 Android 工程编译提供的 **compileOnly** 类型签名桩，**不会被打包进 APK**。运行时依赖 LSPosed 提供的 legacy Xposed API。对应桩源码在 `stubsrc/`。

## 安装

1. 安装构建完成的 APK。
2. LSPosed 中启用 `DNS Observer`，**只勾选「系统框架 / System Framework / system」**，不要勾选全部 App，也不要额外启用「Android 系统 UI」。
3. **完整重启手机**（这是系统进程 Hook，重启 App 不足以生效）。
4. 打开 DNS Observer，页面显示「系统 DNS Hook 已连接」后，用浏览器访问从未访问过的域名，查看新记录。
5. 如果始终没有心跳，先检查 LSPosed 模块日志中 `DNSObserver:` 标签；可能是 ColorOS 修改了 `SystemServer` 或 `NetdEventListenerService` 类位置 / 方法签名。**不要反复重启尝试不明 Hook 修补。**

### 安全提醒

该插件 Hook `system_server`，虽然只读且 Hook 回调不访问磁盘，但此类插件仍存在系统不稳定风险。先确认你已掌握 LSPosed/KernelSU 的模块禁用或恢复方式，再在主力机启用。仅用经过本机构建、审计的 APK；不应对网络解析路径写入或替换返回值。

### 诊断

- LSPosed 日志应包含：`DNSObserver: system DNS hook installed: 1`。
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

## 当前验证状态

完成源代码静态检查、XML 解析检查以及独立 `TextPolicy` JVM 回归测试。当前执行环境没有 Android SDK / Gradle，**未完成 APK 编译或 ColorOS 16 实机运行验证**。发布的是开发验证版源码，不应视作已实测稳定版本。
