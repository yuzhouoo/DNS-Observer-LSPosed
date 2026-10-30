# 域瞳独立后台 v0.7.0-beta1

仅支持 arm64、KernelSU、Mihomo TPROXY，不包含 Mihomo 核心。无 TUN / 多核心 / 自动订阅转换。首次安装默认全部停止。

## 首次迁移

1. 在旧 APK 中关闭并清理接管。备份旧 Box 的核心、完整 YAML、proxy_provider 与规则文件，再停止并卸载 Box（卸载可能删除它的数据目录）。
2. **先安装本模块，再处理 APK。**模块安装时尝试停止旧 APK，并备份用户0的数据库和偏好到 `/data/adb/yutong/app-backup`，不覆盖已有备份。确认安装日志中的备份结果；若备份未确认，先在旧 APK 导出记录。
3. 旧构建调试签名不固定，若无法覆盖安装，确认备份后卸载旧 APK、安装新 APK，**暂不要打开新 APK**。
4. 在 KernelSU 点击本模块“操作”恢复旧记录和参数；已有新数据库时拒绝覆盖。恢复会禁用旧 APP 接管，保留独立后台入口。其他 Android 用户的旧数据需要手动导出，不会自动跨用户读取。
5. 确认 LSPosed 模块与作用域、授权 Root，首次重启。控制台可导入解压后的 arm64 Mihomo ELF 与 YAML。对于相对 provider 路径，将完整配置目录放入 `/data/adb/yutong/mihomo/` 或其他受保护 `/data` 目录，再填写原始 YAML 路径；单个 YAML 导入不包含它引用的 provider 文件。
6. 填入自建 DNS 主/从/备、端口、Bootstrap 纯 IP。先测试“仅 DNS”，确认 IPv4/IPv6 校验结果后再启用“DNS + TPROXY”。启用 SIM MATCH 时填写真实存在的策略组或 DIRECT；SIM未知时暂保留原 MATCH。
7. 按需勾选开机恢复；“全部停止”会持久化，开机不会擅自恢复旧模式。

核心路径默认 `/data/adb/yutong/mihomo/mihomo`，YAML 默认 `config.yaml`；可以导入或指定已有位置。不要把仅有的核心/配置留在待卸载的 Box 目录。

## 运行职责

APK 不是运行进程的父服务。模块开机入口部署静态 arm64 Root 程序，独立 supervisor 启动并监管 manager；manager 内运行 DNS 转发并监管自己的 Mihomo 子进程。APK 划掉/退出不停止它们。supervisor / manager 自身同时被系统或 Root 工具杀死仍可能中断服务，不宣称绝对无法被终止。模块禁用后 supervisor 在约5秒轮询中请求停止，开机不再启动。

三个模式：dns / proxy / off。开关有 IPv4、IPv6、开机恢复、故障自动恢复、代理局域网绕过、代理绕过 UID、DNS 查询日志、外部853限制、按默认移动数据SIM改变最终MATCH。地址族选择同时用于 DNS 与透明代理；IPv4/IPv6 选择不控制 A/AAAA 返回。

DNS-only：客户端 DNS53 → 本地15353 → 自建 DNS。

Proxy：客户端 DNS53 → 本地15353 → Mihomo DNS1053 → 本地上游15354 → 自建 DNS。Mihomo 的普通/节点/直连解析均使用15354。仅 DNS 模式不启动 Mihomo。Mihomo 故障时尝试保留独立 DNS，受限退避重建代理。

Mihomo 的运行 YAML 是副本：统一 Rule、TPROXY9898、关闭TUN/其他入站、自有出站标记、DNS redir-host、回环控制API及随机secret。原始文件不被这些覆盖规则改写。订阅 provider URL、代理组、规则仍由原配置保留；完整客户端式订阅转换和在线编辑不包含在本版。

## 状态与回滚

DNS UDP/TCP 本地预检后，先仅 Root UID 的 DNS53 接管测试，再扩大到本机请求，重复验证。不排除所有 Root UID，转发进程与核心按独立出站 mark 避免回环。修改配置先做结构校验，代理配置先执行用户核心的 `-t`。新模式应用失败时，已有可用模式尝试恢复；原文件被外部修改、上游不可达或内核不支持会使恢复也失败，日志明确记录。

所有自有规则使用 YTDNS 前缀、表19770、pref9000/9001/9100。状态检查对比受保护的完整链快照、有效顺序和路由，不只检查 PID。清理依赖自身所有权记录，不执行全局 flush，不移除其他模块的全局IPv6阻断。Android 的正常终止unreachable不删除。接管运行期间租用 lo 上专用地址198.18.254.1/32与fd53:7974:6f6e::1/128，为无普通路由时的DNS初始选路提供明确源地址；预先存在同址时拒绝安装，停止时只按自身所有权记录删除。IPv6全局关闭与IPv6接管冲突时应明确处理。

双协议运行时，外部IPv6阻断/全局禁用会降级保留正常IPv4，并在条件恢复后尝试恢复IPv6，过程保留DNS工作进程。

网络事件使用 Root netlink，周期检查兜底；无需 APK 发广播维持。新网络恢复后刷新上游IP；暂时失败保留原有端点，不秘密切换公共DNS。Bootstrap仍为明确配置。新上游地址集和UDP/TCP分别验证；UDP失败可改TCP，主不可用再尝试从/备。

853开关只限制启用地址族的 TCP/UDP853，不解密或替换DoT/DoQ，不保证应用回退；不处理DoH/非标准加密DNS端口。默认关闭。

## 调试

`/data/adb/yutong/logs/` 中有 events.jsonl、commands.jsonl、dns.jsonl、mihomo.jsonl、supervisor.log；配置拒绝的核心原始输出在core-validate.log（可能含provider URL，请分享前检查）。事件与命令/DNS日志按2MiB轮转，保留两份历史。DNS记录包含查询名、类型、入站协议、上游、返回码、时间、地址列表；UID未获取时明确为未知。日志有容量边界，不保证无限历史；高负载下需要真机性能评估。

APK 能刷新真实状态、选择 Selector 代理组节点、查看/复制诊断；详细观察打开时，将当前保留窗口的 Root DNS 记录导入原 DNS 列表。APK关闭时 Root日志仍保存，但列表导入在打开控制台后执行，超过轮转窗口的记录不会补回。

自建上游、配置文件和原有日志属于用户数据，卸载模块不删除。需彻底删除时先确认清理完成再手动删除 `/data/adb/yutong`。

真机验收：APK杀进程、重启、断网/恢复、双卡切换、IPv6启停、核心异常退出、规则删除、连续停止/启动及两模式切换。CI测试和构建成功不等于已完成这些设备验收。
