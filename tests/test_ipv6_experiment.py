from pathlib import Path
base=Path(__file__).resolve().parents[1]
script=(base/'app/src/main/assets/dns-ipv6-tproxy-probe.sh').read_text()
ui=(base/'app/src/main/java/dev/yz/dnsobserver/DnsControlActivity.java').read_text()
service=(base/'app/src/main/java/dev/yz/dnsobserver/DnsForwardService.java').read_text()
rules=(base/'app/src/main/java/dev/yz/dnsobserver/DnsRootRules.java').read_text()
assert 'PREROUTING' in script and '--dport 15453' in script
assert '--on-port 15454' in script and '--on-ip ::1' in script
assert '20' in script and 'watch)' in script and 'recover)' in script
assert 'ip6tables -t nat' not in script
assert 'ip -6 rule' not in script and 'route add' not in script
assert 'OUTPUT' not in script.replace('OUTPUT,','')  # no OUTPUT modifications
assert 'DNS 接管' in ui and 'DnsIpv6Experiment.run' in ui and 'DnsIpv6Experiment.recover' in ui
assert 'supportsIpv6Nat(this)' in service and 'useIpv6 = false' in service
assert 'dns-root-v052.sh' in rules # force updated script despite cached v0.3.0
print('PASS: isolated IPv6 chain and automatic IPv4 fallback')
