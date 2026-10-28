from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=(root/'app/src/main/java/dev/yz/dnsobserver/DnsIpv6Experiment.java').read_text()
helper=(root/'app/src/main/java/dev/yz/dnsobserver/DnsIpv6RootProbe.java').read_text()
s=(root/'app/src/main/assets/dns-ipv6-tproxy-probe.sh').read_text()
assert 'CLASSPATH=' in p and '/system/bin/app_process' in p
assert 'DIRECT_OK' in p and 'TPROXY_OK' in p
assert p.index('DIRECT_OK') < p.index('root(ctx,"install"')
assert 'Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,TRANSPARENT_IPV6,1)' in helper
assert 'Os.geteuid()' in helper and 'ERROR errno=' in helper
assert 'IPV6_TRANSPARENT Socket' not in p
assert 'new DatagramSocket(null)' in p # sender only, never fallback receiver
assert 'PREROUTING rule match:' in s and 'TPROXY target match:' in s
assert 'ip -6 rule' not in s and 'route add' not in s
assert '--dport 15453' in s and '--on-port 15454' in s
print('PASS: root transparent socket, staged loopback test, scoped rollback')
