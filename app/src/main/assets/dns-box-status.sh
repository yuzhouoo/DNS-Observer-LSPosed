#!/system/bin/sh
# Read-only Box for Root lifecycle probe. No source of Box settings or rules writes.
[ "$(id -u)" = 0 ] || exit 1
IP=$(command -v ip) || exit 2
IP4=$(command -v iptables) || exit 2
IP6=$(command -v ip6tables) || exit 2
processes=""
for dir in /proc/[0-9]*; do
    IFS= read -r comm < "$dir/comm" 2>/dev/null || continue
    case "$comm" in mihomo|sing-box|xray|v2fly|hysteria) ;; *) continue;; esac
    exe=$(readlink "$dir/exe" 2>/dev/null) || continue
    case "$exe" in
        /data/adb/box/bin/mihomo|/data/adb/box/bin/sing-box|/data/adb/box/bin/xray|/data/adb/box/bin/v2fly|/data/adb/box/bin/hysteria) ;;
        *) continue;;
    esac
    start=$(sed 's/.*) //' "$dir/stat" 2>/dev/null | awk '{print $20}')
    case "$start" in ''|*[!0-9]*) exit 3;; esac
    processes="$processes ${dir##*/}:$start:${exe##*/}"
done
# -S excludes packet counters. Ignore all DNS Observer chains and session markers.
v4=$("$IP4" -w 1 -t mangle -S 2>/dev/null) || exit 4
v6=$("$IP6" -w 1 -t mangle -S 2>/dev/null) || exit 4
n4=$("$IP4" -w 1 -t nat -S 2>/dev/null) || exit 4
n6=$("$IP6" -w 1 -t nat -S 2>/dev/null) || n6='NO_IPV6_NAT'
select_rules() {
    awk '{for(i=1;i<=NF;i++)if($i ~ /^(BOX_[A-Za-z0-9_]*|NAT_DNS_[A-Za-z0-9_]*|DIVERT)$/){print;break}}'
}
rules=$(printf '%s\n' "v4:$v4" "v6:$v6" "nat4:$n4" "nat6:$n6" | select_rules)
# Distinguish families even when they have identical chains. Only Box-known tables.
route_state=""
for family in -4 -6; do
    rr=$("$IP" "$family" rule show 2>/dev/null) || exit 5
    rr=$(printf '%s\n' "$rr" | awk '/lookup (2024|2025)( |$)/ || /^(98|99|100):/')
    for table in 2024 2025; do
        rt=$("$IP" "$family" route show table "$table" 2>/dev/null)
        route_state="$route_state|$family:$table:$rt"
    done
    route_state="$route_state|$family:$rr"
done
fingerprint=$(printf '%s\n' "$v4" | select_rules; printf 'V6\n'; printf '%s\n' "$v6" | select_rules; printf 'N4\n'; printf '%s\n' "$n4" | select_rules; printf 'N6\n'; printf '%s\n' "$n6" | select_rules; printf '%s\n' "$route_state")
sum=$(printf '%s' "$fingerprint" | cksum) || exit 6
if [ -n "$processes" ]; then
    if [ -n "$rules" ]; then state=running; else state=starting; fi
else
    if [ -n "$rules" ]; then state=stopping; else state=stopped; fi
fi
printf 'BOX=%s\nSIGNATURE=%s|%s\n' "$state" "$processes" "$sum"
