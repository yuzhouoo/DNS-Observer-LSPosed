from pathlib import Path
root=Path("app/src/main/java/dev/yz/dnsobserver")
s=(root/"DnsControlActivity.java").read_text()
m=(root/"MainActivity.java").read_text()
c=(root/"DnsIpv6PilotController.java").read_text()
assert 'ClipboardManager' in s and 'ClipData.newPlainText' in s
assert 'setTextIsSelectable(true)' in s
assert 'DnsTakeoverService.clearEvents(this)' in s
assert 'copyText(DnsIpv6GlobalController.report(this)' in s
assert 'clearLog(Context ctx)' in c and '.remove("ipv6_pilot_log").commit()' in c
assert 'ipv6ExperimentResult' not in s
assert '旧版 IPv6 NAT 重定向' not in s
assert 'historyScroll.setVisibility(View.GONE)' in s
assert 'BuildConfig.VERSION_NAME' in s and 'BuildConfig.VERSION_NAME' in m
print('PASS: compact selectable pilot logs, clear and old UI removed')
