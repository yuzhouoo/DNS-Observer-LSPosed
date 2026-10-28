from pathlib import Path
root=Path('app/src/main/java/dev/yz/dnsobserver')
server=(root/'DnsIpv6PilotDaemon.java').read_text()
control=(root/'DnsIpv6PilotController.java').read_text()
exp=(root/'DnsIpv6Experiment.java').read_text()
ui=(root/'DnsControlActivity.java').read_text()
shell=Path('app/src/main/assets/dns-ipv6-tproxy-probe.sh').read_text()
assert 'install-pilot' in shell and 'install-pilot' in exp
assert '"$MODE" = install-dns ] || [ "$MODE" = install-pilot' in shell
assert 'pilot:$TOKEN' in shell and 'deadline=180' in shell and 'deadline=35' in shell
assert 'verify_clean()' in shell and 'clear_owned' in shell
assert 'IPV6_TRANSPARENT' in server and 'SO_REUSEADDR' in server
assert 'LIFETIME_SECONDS=145' in server and 'new ArrayBlockingQueue<>(32)' in server
assert 'new ThreadPoolExecutor(2,4,' in server and 'MAX_DNS=4096' in server
assert 'DnsUpstreamExchange.query' in server and 'DnsPacket.servfail(q)' in server
assert 'Os.recvfrom(listen,data' in server and 'Os.sendto(response,ans' in server
assert 'Os.accept(server,new InetSocketAddress(0))' in server
assert 'Os.write(fd,out,sent' in server and 'if(readExact(fd,q,len)!=len)return' in server
assert 'DnsBootstrap.resolve(host,' in control and 'DnsProbe.measure(ip,port,"UDP")' in control
assert 'DnsProbe.measure(ip,port,"TCP")' in control
assert control.index('preflight(app)')<control.index('root(app,"install-pilot"')
assert 'if(!udp||!tcp)' in control and 'stop(ctx)' in control
assert 'if(ownsRules || (installAttempted' in control and 'PRECHECK_FAILED' in control
assert 'DnsIpv6Experiment.recover(app)' in control and 'DnsIpv6Experiment.recover(ctx)' in control
assert 'DnsIpv6PilotController.start' in ui and 'DnsIpv6PilotController.stop' in ui
assert 'DnsIpv6PilotController.test' in ui and 'DnsIpv6PilotController.isRunning()' in ui
assert '复制完整 IPv6 试运行日志' in ui
assert 'v0.6.0-beta1' in ui
print('PASS: opt-in restricted IPv6 multi-query Root pilot, auto-recovery and UI wiring')
