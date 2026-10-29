"""Fail-safe structure checks; device behavior still requires field diagnostics."""
from pathlib import Path
base=Path('app/src/main/java/dev/yz/dnsobserver')
daemon=(base/'DnsIpv6GlobalDaemon.java').read_text()
control=(base/'DnsIpv6GlobalController.java').read_text()
ui=(base/'DnsControlActivity.java').read_text()
shell=Path('app/src/main/assets/dns-ipv6-global.sh').read_text()
assert 'install-probe|promote|recover|status|check|watch' in shell
assert shell.index('install-probe)') < shell.index('promote)')
assert 'DO6G061' in shell and '19754' in shell and '15010' in shell and '0x40000000/0x40000000' in shell
assert 'local ::/0 dev lo table "$TABLE"' in shell
assert 'OUTPUT' in shell and 'PREROUTING' in shell and '-i lo' in shell
assert '-m owner ! --uid-owner 0' in shell
assert 'PRECHECK_FAILED' in shell and 'VERIFY_CLEAN' in shell and 'clear_owned' in shell
assert 'watch)' in shell and 'kill -0 "$OWNER_PID"' in shell
assert 'route_present' in shell and 'rule_present' in shell
assert 'IPV6_RECVPKTINFO' in daemon and 'Os.recvmsg(udp,msg,0)' in daemon
assert 'IPV6_PKTINFO' in daemon and 'StructCmsghdr' in daemon
assert 'target.isAnyLocalAddress()||target.isLoopbackAddress()' in daemon
assert 'Os.getsockname(fd)' in daemon and 'origin.getPort()!=DNS_PORT' in daemon
assert 'Os.bind(fd,message.target,DNS_PORT)' in daemon
assert 'new ArrayBlockingQueue<>(32)' in daemon and 'TTL_SECONDS=145' not in daemon
assert 'consecutiveFailures%6==0' in daemon
assert 'if(DnsIpv6PilotController.isRunning())' in control
assert 'DnsIpv6GlobalController.isRunning()' in (base/'DnsIpv6PilotController.java').read_text()
assert 'selfTest(app)' in control and 'root(app,"promote",token,12)' in control
assert control.index('if(!selfTest(app))') < control.index('root(app,"promote",token,12)')
assert control.index('preflight(app,allowed)') < control.index('root(app,"install-probe"')
assert 'root(ctx,"recover","cleanup",14)' in control
assert 'installAttempted' in control and 'PRECHECK_FAILED' in control and 'rollbackConfirmed' in control
assert 'DnsIpv6GlobalController.stop' in (base/'DnsTakeoverService.java').read_text() and 'DnsIpv6GlobalController.start' in (base/'DnsTakeoverService.java').read_text()
assert '清空 IPv6 日志' in ui and '复制 IPv6 全部日志' in ui
assert 'logArea(root,ipv6GlobalLog,155)' in ui
assert 'BuildConfig.VERSION_NAME' in ui
print('PASS: global IPv6 opt-in gated, dynamic original destination, owner exclusion, independent watchdog, recovery')
