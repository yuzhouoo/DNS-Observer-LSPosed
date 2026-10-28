from pathlib import Path
root=Path("app/src/main/java/dev/yz/dnsobserver")
s=(root/"DnsControlActivity.java").read_text()
m=(root/"MainActivity.java").read_text()
assert 'ClipboardManager' in s and 'ClipData.newPlainText' in s
assert 'setTextIsSelectable(true)' in s
assert '复制完整 IPv6 调试日志' in s and 'copyVisibleText(ipv6ExperimentResult,' in s
assert 'ipv6_last_report' in s and 'showExperimentLog(combined)' in s
assert '复制当前 DNS 测速历史' in s and 'selectable(label("正在加载历史' in s
assert '复制该组 IP 测速明细' in s and 'detailView.setVisibility' in s
assert 'v0.6.0' in s and 'v0.6.0' in m
assert 'setText("正在安装隔离测试规则…")' not in s
print("PASS: full-copy and selectable diagnostic log wiring")
