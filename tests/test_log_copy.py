from pathlib import Path
root=Path("app/src/main/java/dev/yz/dnsobserver")
s=(root/"DnsControlActivity.java").read_text()
m=(root/"MainActivity.java").read_text()
c=(root/"DnsIpv6PilotController.java").read_text()
assert 'ClipboardManager' in s and 'ClipData.newPlainText' in s
assert 'setTextIsSelectable(true)' in s
assert '复制完整 IPv6 试运行日志' in s
assert 'copyText(pilotLog(),"IPv6 试运行日志")' in s
assert '查看完整 IPv6 试运行日志' in s
assert '清空 IPv6 试运行日志' in s and 'DnsIpv6PilotController.clearLog(this)' in s
assert 'clearLog(Context ctx)' in c and '.remove("ipv6_pilot_log").commit()' in c
assert 'ipv6ExperimentResult' not in s
assert '旧版 IPv6 NAT 重定向' not in s
assert '展开最近测速历史' in s and 'history.setVisibility(View.GONE)' in s
assert 'v0.6.0-beta2' in s and 'v0.6.0-beta2' in m
print('PASS: compact selectable pilot logs, clear and old UI removed')
