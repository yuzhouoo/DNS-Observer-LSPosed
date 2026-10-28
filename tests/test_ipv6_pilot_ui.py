from pathlib import Path
root=Path('app/src/main/java/dev/yz/dnsobserver')
ui=(root/'DnsControlActivity.java').read_text()
ctl=(root/'DnsIpv6PilotController.java').read_text()
daemon=(root/'DnsIpv6PilotDaemon.java').read_text()
assert '清空 IPv6 试运行日志' in ui
assert 'prefs.edit().remove("ipv6_last_report").apply()' in ui
assert '.remove("ipv6_pilot_log").commit()' in ctl
assert 'showCompletePilotLog()' in ui and 'refreshPilotPreview()' in ui
assert 'lines.length-6' in ui and 'copyText(pilotLog()' in ui
assert 'DnsIpv6Experiment.run(this)' not in ui
assert 'DnsIpv6Experiment.recover(getApplicationContext())' in ui
assert 'i.putExtra("ipv6",false)' in ui
assert 'putBoolean("ipv6",false)' in ui
assert 'history.setVisibility(View.GONE)' in ui and 'historyExpanded' in ui
assert 'DnsIpv6PilotController.stress(' in ui and 'Executors.newFixedThreadPool(4)' in ctl
assert 'i%2==0' in ctl and 'i<12' in ctl
assert 'UDP_OK bytes=' in daemon and 'TCP_OK bytes=' in daemon
assert 'line.startsWith("DNS6PILOT UDP_OK")' in ctl and 'line.startsWith("DNS6PILOT TCP_OK")' in ctl
assert 'LIFETIME_SECONDS=145' in daemon
print('PASS: beta2 compact log UI, real clearing, disabled legacy IPv6 NAT, bounded 12-way probe')
