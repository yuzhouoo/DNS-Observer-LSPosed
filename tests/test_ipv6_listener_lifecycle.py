from pathlib import Path
base=Path("app/src/main/java/dev/yz/dnsobserver")
probe=(base/"DnsIpv6RootProbe.java").read_text()
exp=(base/"DnsIpv6Experiment.java").read_text()
assert 'private static final int DIRECT_TCP_PORT=15455;' in probe
assert 'private static final int DIRECT_TCP_PORT=15455;' in exp
assert 'tcp && "DIRECT".equals(stage)?DIRECT_TCP_PORT:LISTEN_PORT' in probe
assert '"TCP".equals(proto)?DIRECT_TCP_PORT:LISTEN_PORT' in exp
assert 'Os.setsockoptInt(listen,OsConstants.SOL_SOCKET,OsConstants.SO_REUSEADDR,1)' in probe
assert probe.index('if(accepted!=null)try{Os.close(accepted)') < probe.index('say(outcome);')
assert probe.index('if(listen!=null)try{Os.close(listen)') < probe.index('say(outcome);')
assert 'say("CLOSED protocol="+proto+" stage="+stage);' in probe
assert '"RECV_OK protocol="+proto' in probe
assert 'proc.waitFor(1200,TimeUnit.MILLISECONDS)' in exp
print("PASS: TCP direct isolation, listener closes before RECV_OK, process-exit grace")
