from pathlib import Path
import xml.etree.ElementTree as ET
root=Path('app/src/main/java/dev/yz/dnsobserver')
ui=(root/'DnsControlActivity.java').read_text()
controller=(root/'DnsTakeoverService.java').read_text()
boot=(root/'DnsBootReceiver.java').read_text()
globalctl=(root/'DnsIpv6GlobalController.java').read_text()
globald=(root/'DnsIpv6GlobalDaemon.java').read_text()
bootstrap=(root/'DnsBootstrap.java').read_text()
v4=(root/'DnsRootRules.java').read_text()
shell=Path('app/src/main/assets/dns-ipv6-global.sh').read_text()
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
assert 'takeIpv4=new CheckBox' in ui and 'takeIpv6=new CheckBox' in ui
assert 'takeIpv4.isChecked()' in ui and 'takeIpv6.isChecked()' in ui
assert 'repairSwitch=new Switch' in ui and 'bootSwitch=new Switch' in ui
assert 'DnsTakeoverService.requestStop(this)' in ui
assert 'DnsTakeoverService.requestStart(this)' in ui
assert 'ScrollView box=new ScrollView(this)' in ui and 'box.setNestedScrollingEnabled(true)' in ui
assert 'logArea(root,takeoverEvents,145)' in ui and 'logArea(root,ipv6GlobalLog,155)' in ui
assert 'DnsTakeoverService.clearEvents(this)' in ui
assert 'DnsRootRules.remove(this)' in controller
assert 'DnsIpv6GlobalController.stop(this)' in controller
assert 'DnsIpv6PilotController.stop(this)' in controller and 'DnsIpv6Experiment.recover(this)' in controller
assert 'putBoolean("takeover_enabled",false).commit()' in controller
assert 'if(stopped || !prefs().getBoolean("takeover_enabled",false))break;' in controller
assert 'DETECT: IPv4' in controller and 'DETECT: IPv6' in controller
assert 'boolean heal=p.getBoolean("takeover_auto_repair",false)' in controller
assert 'if(heal)' in controller and 'REPAIR:' in controller
assert 'ACTION_BOOT_COMPLETED' in boot and 'takeover_boot' in boot and 'takeover_enabled' in boot
assert 'RECEIVE_BOOT_COMPLETED' in manifest and '.DnsBootReceiver' in manifest and '.DnsTakeoverService' in manifest
assert 'InetAddress.getAllByName' not in bootstrap.split('public static InetAddress[] resolve(String host, String backupIp) throws Exception {')[1].split('public static InetAddress[] resolveOnlyViaBackup')[0]
assert 'return resolveOnlyViaBackup(name,backupIp);' in bootstrap
assert 'DnsBootstrap.parseLiteral' in controller
assert 'install-probe|promote|recover|status|check|watch' in shell
assert 'if verify_clean' in shell
assert 'while :' in shell and 'OWNER_PID' in shell and 'kill -0 "$OWNER_PID"' in shell
assert '"$n" -lt 180' not in shell
assert 'TTL_SECONDS=145' not in globald
assert 'System.nanoTime()<limit' not in globald
assert 'consecutiveFailures>=6' not in globald
assert 'public static boolean active(Context ctx)' in globalctl
assert 'dns-ipv6-global-v062.sh' in globalctl
assert 'dns-root-v062.sh' in v4
print('PASS: IPv4/IPv6 independent, force stop, timed watchdog removed, boot and opt-in repair, Bootstrap-only, scroll logs')
