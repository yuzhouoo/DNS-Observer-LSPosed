from pathlib import Path
root=Path(__file__).resolve().parents[1]
e=(root/'app/src/main/java/dev/yz/dnsobserver/DnsIpv6Experiment.java').read_text()
h=(root/'app/src/main/java/dev/yz/dnsobserver/DnsIpv6RootProbe.java').read_text()
s=(root/'app/src/main/assets/dns-ipv6-tproxy-probe.sh').read_text()
assert 'CLASSPATH=' in e and '/system/bin/app_process' in e
assert 'Os.setsockoptInt(listen,OsConstants.IPPROTO_IPV6,IPV6_TRANSPARENT,1)' in h
assert 'Os.geteuid()' in h and 'ERROR errno=' in h
assert 'Os.accept(listen,new InetSocketAddress(0))' in h
assert 'RECV_OK protocol=' in h
assert 'new DatagramSocket(null)' in e # sending only, never fallback receiver
assert 'install-loop' in e and 'install-local' in e and 'install-dns' in e
assert 'DnsPacket.probeQuestion()' in e and 'DnsPacket.validQuestion(query)' in h
assert e.index('"UDP","DIRECT"') < e.index('"install-loop"')
assert e.index('loopUdp=single') < e.index('"install-local"')
assert 'if(!clean || !loopUdp || !loopTcp)' in e
assert 'finally{cleanup(ctx,report);}' in e
assert 'VERIFY_CLEAN' in s and 'VERIFY_FAILED' in s
print('PASS: TCP+UDP root socket and staged recovery')
