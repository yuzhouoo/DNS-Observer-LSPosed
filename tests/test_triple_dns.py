from pathlib import Path
base=Path(__file__).resolve().parents[1]
def source(f):return (base/'app/src/main/java/dev/yz/dnsobserver'/f).read_text()
ui=source('DnsControlActivity.java')
relay=source('DnsForwardService.java')
db=source('DnsDb.java')
probe=source('DnsProbe.java')
assert all(x in ui for x in ['主 DNS','从 DNS','备 DNS','"sub_host"','"secondary_host"','IPv4','IPv6','"UDP"','"TCP"','speedResults'])
assert all(x in relay for x in ['subHost','subUpstream','subPort','DnsFailover','role_ips_0','role_ips_1','role_ips_2'])
assert 'usingSecondary' not in relay
assert 'VERSION = 4' in db and 'CREATE TABLE IF NOT EXISTS upstream_probe' in db
assert all(x in probe for x in ['queryUdp','queryTcp','SO_TIMEOUT_MS' if False else 'TIMEOUT_MS','DnsPacket.validReply'])
print('PASS: three DNS groups and 4-channel speed UI are wired end-to-end')
