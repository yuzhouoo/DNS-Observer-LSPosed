from pathlib import Path
base=Path(__file__).resolve().parents[1]
s=(base/'app/src/main/assets/dns-ipv6-tproxy-probe.sh').read_text()
ui=(base/'app/src/main/java/dev/yz/dnsobserver/DnsControlActivity.java').read_text()
service=(base/'app/src/main/java/dev/yz/dnsobserver/DnsForwardService.java').read_text()
rules=(base/'app/src/main/java/dev/yz/dnsobserver/DnsRootRules.java').read_text()
assert 'DO6TST55' in s and 'install-loop|install-local|install-dns|install-pilot|recover|status|watch' in s
assert '--on-port "$PROXY"' in s and '--on-ip ::1' in s
assert 'watch)' in s and 'verify_clean()' in s and '35' in s
assert 'ip6tables -t nat' not in s
assert 'DNS_PORT=53' in s and 'install-dns' in s
assert '-m mark --mark "$MARK"' in s
assert 'dns-ipv6-probe-v060.sh' in (base/'app/src/main/java/dev/yz/dnsobserver/DnsIpv6Experiment.java').read_text()
assert '2001:db8:ffff::53' in s and '15453' in s and '15454' in s
assert '-m owner --uid-owner "$UID_ARG"' in s and 'OUTPUT 1' in s
assert 'route add local "$TEST_ADDR" dev lo table "$TABLE"' in s
assert 'rule add pref "$PREF" fwmark "$MARK" lookup "$TABLE"' in s
assert 'rule del pref "$PREF" fwmark "$MARK" lookup "$TABLE"' in s
assert 'route del local "$TEST_ADDR" dev lo table "$TABLE"' in s
assert '^[[:space:]]*15000:' in s and "route show table \"$TABLE\"" in s
assert 'DnsIpv6Experiment.run' not in ui and 'DnsIpv6Experiment.recover(this)' in (base/'app/src/main/java/dev/yz/dnsobserver/DnsTakeoverService.java').read_text()
assert 'supportsIpv6Nat(this)' in service and 'useIpv6 = false' in service
assert 'dns-root-v062.sh' in rules
print('PASS: scoped local-v6 TPROXY experiment and IPv4 fallback')
