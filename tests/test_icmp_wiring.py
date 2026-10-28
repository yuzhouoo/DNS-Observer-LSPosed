from pathlib import Path
base=Path('app/src/main/java/dev/yz/dnsobserver')
mon=(base/'UpstreamMonitor.java').read_text()
assert 'if(!quick) tasks.add(()->DnsIcmpProbe.measure(addr));' in mon
assert 's.success && !"PING".equals(s.transport)' in mon
assert 'DnsDiagnosis.forAddress' in mon
assert '"PING"' in (base/'DnsControlActivity.java').read_text()
print("PASS: ICMP results isolated from DNS server health")
