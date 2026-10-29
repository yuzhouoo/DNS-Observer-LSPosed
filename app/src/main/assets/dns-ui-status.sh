#!/system/bin/sh
# Read-only feature status probe. No rule, route or sysctl mutations.
set -u
uid=${1:-}
case "$uid" in ''|*[!0-9]*) exit 2;; esac
[ "$(id -u)" = 0 ] || exit 3
if rules=$(iptables -w 2 -t nat -S 2>/dev/null); then
    if printf '%s\n' "$rules" | grep -q 'DOBSR53' || [ -f "/data/local/tmp/dobsr53_${uid}.run" ]; then
        echo V4=present
    else echo V4=off; fi
else echo V4=unknown; fi
# If mangle is unavailable but IPv6 is fully disabled, IPv6 rules still remain unknown.
if rules=$(ip6tables -w 2 -t mangle -S 2>/dev/null) && routes=$(ip -6 rule show 2>/dev/null); then
    if printf '%s\n%s\n' "$rules" "$routes" | grep -Eq 'DO6G061|DO6TST55|15010:|15000:|0x40000000|0x20000000' ||
       [ -f "/data/local/tmp/dobs6g61_${uid}.run" ] || [ -f "/data/local/tmp/dobs6t55_${uid}.run" ]; then
        echo V6=present
    else
        # Missing tables commonly return rc=2; an existing nonempty table indicates residue.
        table=$(ip -6 route show table 19754 2>/dev/null || true)
        pilot=$(ip -6 route show table 19753 2>/dev/null || true)
        if [ -n "$table$pilot" ]; then echo V6=present; else echo V6=off; fi
    fi
else echo V6=unknown; fi
zero=0; one=0; bad=0
for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [ -f "$f" ] || continue
    case "$(cat "$f" 2>/dev/null)" in 0) zero=$((zero+1));; 1) one=$((one+1));; *) bad=1;; esac
done
if [ "$bad" = 1 ] || [ "$((zero+one))" = 0 ]; then echo SYSTEM=unknown
elif [ "$zero" = 0 ]; then echo SYSTEM=disabled
elif [ "$one" = 0 ]; then echo SYSTEM=enabled
else echo SYSTEM=mixed; fi
