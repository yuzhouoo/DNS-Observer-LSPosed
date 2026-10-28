from pathlib import Path
base=Path("app/src/main/java/dev/yz/dnsobserver")
exp=(base/"DnsIpv6Experiment.java").read_text()
root=(base/"DnsIpv6RootProbe.java").read_text()
helper=(base/"DnsUpstreamExchange.java").read_text()
assert '"UPSTREAM".equals(stage)' in exp and '"UPSTREAM".equals(stage)' in root
assert 'if(DnsRootRules.active(ctx))' in exp
assert exp.index('selectUpstream(ctx,"UDP",report)') < exp.index('root(ctx,"install-dns",token,10)',exp.index('selectUpstream(ctx,"UDP",report)'))
assert 'DnsBootstrap.resolve(host,bootstrap)' in exp
assert 'DnsProbe.measure(addr,port,protocol)' in exp
assert 'DnsUpstreamExchange.permittedUpstream' in root
assert 'DnsUpstreamExchange.query(upstream,port,proto,query)' in root
assert 'Os.bind(replySocket,InetAddress.getByName(DOC_IP),DNS_PORT)' in root
assert '(b[0]&255)==0x20' in helper and '(b[2]&255)==0x0d' in helper and '(b[3]&255)==0xb8' in helper
print("PASS: upstream configured-only, bounded IP, preflight before installation, Root reply path")
