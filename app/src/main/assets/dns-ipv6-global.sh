#!/system/bin/sh
# DNS Observer IPv6 global unicast DNS53 trial (explicit opt-in only).
# Dedicated chain, mark, route table and watchdog; do not touch existing Android rules.
set -u
MODE="${1:-}"; APP_UID="${2:-}"; TOKEN="${3:-}"; OWNER_PID="${4:-}"; TARGET_PID="${5:-}"
CHAIN=DO6G061; TABLE=19754; PREF=15010
MARK=0x40000000/0x40000000; PROXY=15456
MARKER="/data/local/tmp/dobs6g61_${APP_UID}.run"
case "$MODE" in install-probe|promote|recover|status|check|watch|stop-process|stop-owned-daemons) ;; *) exit 2;; esac
case "$APP_UID" in ''|*[!0-9]*) exit 2;; esac
case "$TOKEN" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
IP6="$(command -v ip6tables 2>/dev/null || true)"
IP="$(command -v ip 2>/dev/null || true)"
[ -n "$IP6" ] && [ -n "$IP" ] || { echo 'PRECHECK_FAILED: ip/ip6tables missing' >&2; exit 3; }

# Both probe and global rules are exclusively in locally-generated OUTPUT.
# Exclude UID 0 for Root proxy outbound queries so the proxy cannot intercept itself.
# Cover IPv6 global-unicast and ULA, not multicast/link-local/loopback.
del_jumps() {
    for proto in udp tcp; do
        n=0
        while "$IP6" -w 1 -t mangle -C PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1; do
            "$IP6" -w 1 -t mangle -D PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 || break
            n=$((n+1)); [ "$n" -lt 8 ] || break
        done
        for subnet in '2000::/3' 'fc00::/7'; do
            n=0
            while "$IP6" -w 1 -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1; do
                "$IP6" -w 1 -t mangle -D OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || break
                n=$((n+1)); [ "$n" -lt 8 ] || break
            done
            n=0
            while "$IP6" -w 1 -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1; do
                "$IP6" -w 1 -t mangle -D OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || break
                n=$((n+1)); [ "$n" -lt 8 ] || break
            done
        done
    done
}
owned() {
    [ -f "$MARKER" ] || "$IP6" -w 1 -t mangle -S "$CHAIN" >/dev/null 2>&1 ||
    "$IP6" -w 1 -t mangle -C PREROUTING -i lo -p udp --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 ||
    "$IP6" -w 1 -t mangle -C PREROUTING -i lo -p tcp --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1
}
route_present() {
    "$IP" -6 route show table "$TABLE" 2>/dev/null | awk '
      $1=="local" && ($2=="::/0" || $2=="default") {
        for(i=3;i<NF;i++)if($i=="dev" && $(i+1)=="lo")found=1
      } END {exit !found}'
}
rule_present() {
    "$IP" -6 rule show 2>/dev/null | awk '
      $1=="15010:" {
        mark=0;table=0
        for(i=2;i<NF;i++){
          if($i=="fwmark" && (tolower($(i+1))=="0x40000000/0x40000000" || $(i+1)=="1073741824/1073741824"))mark=1
          if(($i=="lookup" || $i=="table") && $(i+1)=="19754")table=1
        }
        if(mark && table)found=1
      } END {exit !found}'
}
clear_owned() {
    owned || return 0
    del_jumps
    "$IP6" -w 1 -t mangle -F "$CHAIN" >/dev/null 2>&1 || true
    "$IP6" -w 1 -t mangle -X "$CHAIN" >/dev/null 2>&1 || true
    if rule_present; then "$IP" -6 rule del pref "$PREF" fwmark "$MARK" lookup "$TABLE" >/dev/null 2>&1 || true; fi
    if route_present; then "$IP" -6 route del local ::/0 dev lo table "$TABLE" >/dev/null 2>&1 || true; fi
}
verify_clean() {
    bad=0
    "$IP6" -w 1 -t mangle -L PREROUTING -n >/dev/null 2>&1 || bad=1
    "$IP6" -w 1 -t mangle -L OUTPUT -n >/dev/null 2>&1 || bad=1
    "$IP" -6 rule show >/dev/null 2>&1 || bad=1
    for proto in udp tcp; do
        "$IP6" -w 1 -t mangle -C PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 && bad=1
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -w 1 -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 && bad=1
            "$IP6" -w 1 -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1 && bad=1
        done
    done
    "$IP6" -w 1 -t mangle -S "$CHAIN" >/dev/null 2>&1 && bad=1
    rule_present && bad=1
    route_present && bad=1
    if [ "$bad" -eq 0 ]; then echo 'VERIFY_CLEAN: global module rules and routes absent'; return 0; fi
    echo 'VERIFY_FAILED: global module residue; manual cleanup required' >&2; return 1
}
# Android kernels return EACCES for a route whose nexthop has disable_ipv6=1.
# Only temporarily enable lo; never override a system-wide IPv4-only choice.
CONF=/proc/sys/net/ipv6/conf
BOOT_FILE=/proc/sys/kernel/random/boot_id
LO_STATE="/data/adb/dnsobserver-v6-lo_${APP_UID}"
network_diagnostics() {
    echo "IPV6_ROUTE_CONTEXT uid=$(id -u) context=$(cat /proc/self/attr/current 2>/dev/null)"
    grep -E '^(CapEff|CapPrm):' /proc/self/status 2>/dev/null || true
    for iface in all default lo; do
        echo "disable_ipv6.$iface=$(cat "$CONF/$iface/disable_ipv6" 2>/dev/null || echo unknown)"
    done
    "$IP" -6 addr show dev lo 2>&1 || true
}
restore_loopback() {
    [ -f "$LO_STATE" ] || return 0
    read -r saved_boot saved_token saved_value extra < "$LO_STATE" || return 1
    case "$saved_value" in 0|1) ;; *) echo LOOPBACK_RESTORE_FAILED: invalid snapshot; return 1;; esac
    [ -z "$extra" ] || return 1
    boot=$(cat "$BOOT_FILE") || return 1
    if [ "$boot" != "$saved_boot" ]; then rm -f "$LO_STATE"; return $?; fi
    # Normal session cleanup is token scoped; explicit cleanup may recover an orphan.
    [ "$TOKEN" = cleanup ] || [ "$TOKEN" = "$saved_token" ] || { echo LOOPBACK_RESTORE_REFUSED: another session; return 1; }
    printf '%s\n' "$saved_value" > "$CONF/lo/disable_ipv6" || { echo LOOPBACK_RESTORE_FAILED: write denied; return 1; }
    [ "$(cat "$CONF/lo/disable_ipv6")" = "$saved_value" ] || { echo LOOPBACK_RESTORE_FAILED: readback mismatch; return 1; }
    rm -f "$LO_STATE" || return 1
    echo "LOOPBACK_RESTORED: disable_ipv6=$saved_value"
}
prepare_loopback() {
    all=$(cat "$CONF/all/disable_ipv6") || return 1
    default=$(cat "$CONF/default/disable_ipv6") || return 1
    lo=$(cat "$CONF/lo/disable_ipv6") || return 1
    if [ "$all" != 0 ] || [ "$default" != 0 ]; then
        echo 'IPV6_SYSTEM_DISABLED: 请先关闭系统 IPv6 禁用功能，再开启 IPv6 DNS 接管' >&2
        return 1
    fi
    case "$lo" in
      0) echo LOOPBACK_READY: IPv6 already enabled; return 0;;
      1) ;;
      *) echo LOOPBACK_PRECHECK_FAILED: unknown kernel value; return 1;;
    esac
    [ ! -e "$LO_STATE" ] && [ ! -L "$LO_STATE" ] || { echo LOOPBACK_PRECHECK_FAILED: previous snapshot exists; return 1; }
    umask 077
    boot=$(cat "$BOOT_FILE") || return 1
    # noclobber prevents replacing an earlier lease; only root can access /data/adb.
    (set -C; printf '%s %s %s\n' "$boot" "$TOKEN" "$lo" > "$LO_STATE") || return 1
    printf '0\n' > "$CONF/lo/disable_ipv6" || return 1
    [ "$(cat "$CONF/lo/disable_ipv6")" = 0 ] || return 1
    echo LOOPBACK_TEMP_ENABLED: original=1 current=0
}
rollback_owned() {
    clear_owned
    if verify_clean && restore_loopback; then rm -f "$MARKER"; return 0; fi
    echo ROLLBACK_UNCONFIRMED: rules or loopback snapshot retained >&2
    return 1
}

case "$MODE" in
 stop-owned-daemons)
    # Explicit user STOP only. Kill exclusively DNS Observer global Root
    # processes identified by their exact Java class or our unique nice-name.
    # Never kill all app_process instances and never terminate by port alone.
    count=0; pending=""
    for proc in /proc/[0-9]*; do
        pid="${proc##*/}"
        case "$pid" in ''|*[!0-9]*) continue;; esac
        [ "$pid" -gt 1 ] || continue
        [ -r "$proc/cmdline" ] && [ -r "$proc/status" ] || continue
        cmd="$(tr '\000' ' ' < "$proc/cmdline" 2>/dev/null)"
        case "$cmd" in
            *dev.yz.dnsobserver.DnsIpv6GlobalDaemon*|*dobs6_*) ;;
            *) continue;;
        esac
        owner="$(awk '/^Uid:/ {print $2; exit}' "$proc/status" 2>/dev/null)"
        [ "$owner" = 0 ] || continue
        if kill -TERM "$pid" 2>/dev/null; then
            count=$((count+1)); pending="$pending $pid"
        fi
    done
    # A Root app_process may linger briefly after su exits; wait before
    # declaring the address free, then revalidate identity before any KILL.
    if [ "$count" -gt 0 ]; then sleep 1; fi
    remaining=0
    for pid in $pending; do
        [ -r "/proc/$pid/cmdline" ] && [ -r "/proc/$pid/status" ] || continue
        cmd="$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        case "$cmd" in
            *dev.yz.dnsobserver.DnsIpv6GlobalDaemon*|*dobs6_*) ;;
            *) continue;;
        esac
        owner="$(awk '/^Uid:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null)"
        [ "$owner" = 0 ] || continue
        kill -KILL "$pid" 2>/dev/null || true
        remaining=$((remaining+1))
    done
    echo "OWNED_DAEMON_STOP: verified=$count forced=$remaining (PID ownership checked)"
    ;;
 stop-process)
    case "$TARGET_PID" in ''|*[!0-9]*) echo 'PROCESS_STOP_REFUSED: invalid PID' >&2; exit 13;; esac
    [ "$TARGET_PID" -gt 1 ] || { echo 'PROCESS_STOP_REFUSED: protected PID' >&2; exit 13; }
    # This process may be unrelated. Require this exact app session token
    # in its command line; never use pkill -f or kill an unverified PID.
    if [ ! -r "/proc/$TARGET_PID/cmdline" ]; then echo 'PROCESS_STOPPED: PID absent'; exit 0; fi
    owned_cmd="$(tr '\000' ' ' < "/proc/$TARGET_PID/cmdline" 2>/dev/null)"
    case "$owned_cmd" in
       *dobs6_"$TOKEN"*|*dev.yz.dnsobserver.DnsIpv6GlobalDaemon*"$TOKEN"*) ;;
       *) echo 'PROCESS_STOP_REFUSED: PID/token ownership not verified' >&2; exit 13;;
    esac
    kill -TERM "$TARGET_PID" 2>/dev/null || true
    n=0
    while kill -0 "$TARGET_PID" 2>/dev/null && [ "$n" -lt 3 ]; do
        sleep 1; n=$((n+1))
    done
    if kill -0 "$TARGET_PID" 2>/dev/null; then
        current="$(tr '\000' ' ' < "/proc/$TARGET_PID/cmdline" 2>/dev/null)"
        case "$current" in
           *dobs6_"$TOKEN"*|*dev.yz.dnsobserver.DnsIpv6GlobalDaemon*"$TOKEN"*) kill -KILL "$TARGET_PID" 2>/dev/null || true;;
           *) echo 'PROCESS_STOP_REFUSED: PID changed before SIGKILL' >&2; exit 13;;
        esac
    fi
    echo 'PROCESS_STOP: Root daemon termination requested for verified PID'
    ;;
 recover)
    clear_owned
    if verify_clean && restore_loopback; then rm -f "$MARKER"; echo 'RECOVERED: verified clean'; else exit 11; fi
    ;;
 check)
    [ "$(cat "$MARKER" 2>/dev/null)" = "global:$TOKEN" ] || { echo CHECK_FAILED: session marker mismatch; exit 1; }
    "$IP6" -w 1 -t mangle -S "$CHAIN" >/dev/null 2>&1 || { echo CHECK_FAILED: TPROXY chain missing; exit 1; }
    rule_present || { echo CHECK_FAILED: policy rule missing; "$IP" -6 rule show; exit 1; }
    route_present || { echo CHECK_FAILED: local loopback route missing; "$IP" -6 route show table "$TABLE"; exit 1; }
    for proto in udp tcp; do
        "$IP6" -w 1 -t mangle -C PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 || { echo "CHECK_FAILED: PREROUTING $proto selector missing"; exit 1; }
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -w 1 -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || { echo "CHECK_FAILED: OUTPUT $proto $subnet selector missing"; exit 1; }
        done
    done
    echo 'ACTIVE: IPv6 TPROXY selectors complete'
    ;;
 status)
    network_diagnostics
    echo 'OUTPUT/PREROUTING:'
    "$IP6" -w 1 -t mangle -L OUTPUT -n -v -x 2>&1 | grep -E '2000::/3|fc00::/7' || true
    "$IP6" -w 1 -t mangle -L PREROUTING -n -v -x 2>&1 | grep "$CHAIN" || true
    "$IP6" -w 1 -t mangle -L "$CHAIN" -n -v -x 2>&1 || true
    "$IP" -6 rule show | grep '15010:' || true
    "$IP" -6 route show table "$TABLE" 2>&1
    ;;
 install-probe)
    # Never accept an existing marker, table, chain, pref or pre-used fwmark.
    if "$IP6" -w 1 -t mangle -S DO6TST55 >/dev/null 2>&1; then
        echo 'PRECHECK_FAILED: legacy IPv6 pilot chain present; recover pilot first' >&2; exit 4
    fi
    if [ -f "$MARKER" ] || "$IP6" -w 1 -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        echo 'PRECHECK_FAILED: previous global test exists' >&2; exit 4
    fi
    if "$IP" -6 rule show | grep -Eq '^[[:space:]]*15010:' ||
       [ -n "$("$IP" -6 route show table "$TABLE" 2>/dev/null)" ]; then
        echo 'PRECHECK_FAILED: reserved route/pref occupied (15010 / table 19754)' >&2
        "$IP" -6 rule show | grep '15010:' >&2 || true
        "$IP" -6 route show table "$TABLE" >&2 || true
        exit 4
    fi
    if "$IP6" -w 1 -t mangle -S 2>/dev/null | grep -q '0x40000000'; then
        echo 'PRECHECK_FAILED: reserved mark already used' >&2; exit 4
    fi
    "$IP6" -w 1 -t mangle -m owner -h >/dev/null 2>&1 || { echo 'PRECHECK_FAILED: owner match unavailable' >&2; exit 4; }
    "$IP6" -w 1 -t mangle -j TPROXY -h >/dev/null 2>&1 || { echo 'PRECHECK_FAILED: TPROXY missing' >&2; exit 4; }
    if [ -e "$LO_STATE" ] || [ -L "$LO_STATE" ]; then
        echo 'PRECHECK_FAILED: previous loopback snapshot exists; close/cleanup before retry' >&2
        exit 4
    fi
    printf 'probe:%s\n' "$TOKEN" > "$MARKER" || exit 5
    chmod 600 "$MARKER" || true
    # Crash-only guard, NO periodic expiration. This guard releases stale rules
    # only when the owning Android process disappears, never after a TTL.
    case "$OWNER_PID" in ''|*[!0-9]*) echo 'PRECHECK_FAILED: missing owner PID' >&2; rm -f "$MARKER"; exit 4;; esac
    /system/bin/sh "$0" watch "$APP_UID" "$TOKEN" "$OWNER_PID" </dev/null >/dev/null 2>&1 &
    "$IP6" -w 1 -t mangle -N "$CHAIN" || { rollback_owned; exit 5; }
    for proto in udp tcp; do
        "$IP6" -w 1 -t mangle -A "$CHAIN" -p "$proto" -j TPROXY --on-ip ::1 --on-port "$PROXY" --tproxy-mark "$MARK" || { rollback_owned; exit 6; }
    done
    if ! prepare_loopback; then
        network_diagnostics >&2
        rollback_owned; exit 7
    fi
    if ! "$IP" -6 route add local ::/0 dev lo table "$TABLE"; then
        echo 'ROUTE_INSTALL_FAILED: local ::/0 dev lo table 19754; inspect interface/capability/SELinux context above' >&2
        network_diagnostics >&2
        rollback_owned; exit 7
    fi
    "$IP" -6 rule add pref "$PREF" fwmark "$MARK" lookup "$TABLE" || { rollback_owned; exit 8; }
    for proto in udp tcp; do
        "$IP6" -w 1 -t mangle -I PREROUTING 1 -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" || { rollback_owned; exit 9; }
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -w 1 -t mangle -I OUTPUT 1 -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" || { rollback_owned; exit 10; }
        done
    done
    echo 'INSTALLED_PROBE: App UID only, multi-destination original-dst selftest'
    ;;
 promote)
    if [ "$(cat "$MARKER" 2>/dev/null)" != "probe:$TOKEN" ]; then
        echo 'PRECHECK_FAILED: no owned probe session' >&2; exit 4
    fi
    for proto in udp tcp; do
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -w 1 -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || { echo 'PRECHECK_FAILED: selftest rule missing' >&2; exit 4; }
        done
    done
    # Add broad rule only on explicit user opt-in AFTER successful selftest.
    # Root UID 0 excluded to prevent DNS forwarding recursion.
    for proto in udp tcp; do
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -w 1 -t mangle -I OUTPUT 1 -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" || { rollback_owned; exit 10; }
        done
    done
    for proto in udp tcp; do
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -w 1 -t mangle -D OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" || { rollback_owned; exit 11; }
        done
    done
    printf 'global:%s\n' "$TOKEN" > "$MARKER" || { rollback_owned; exit 12; }
    echo 'PROMOTED: globally scoped non-root IPv6 unicast DNS53, UID 0 excluded'
    ;;
 watch)
    case "$OWNER_PID" in ''|*[!0-9]*) exit 2;; esac
    while :; do
        state="$(cat "$MARKER" 2>/dev/null)"
        [ "$state" = "probe:$TOKEN" ] || [ "$state" = "global:$TOKEN" ] || exit 0
        if ! kill -0 "$OWNER_PID" 2>/dev/null; then break; fi
        case "$(tr '\000' ' ' < "/proc/$OWNER_PID/cmdline" 2>/dev/null)" in
            *dev.yz.dnsobserver*) ;;
            *) break;;
        esac
        sleep 5
    done
    state="$(cat "$MARKER" 2>/dev/null)"
    if [ "$state" = "probe:$TOKEN" ] || [ "$state" = "global:$TOKEN" ]; then
        clear_owned
        if verify_clean && restore_loopback; then rm -f "$MARKER"; fi
    fi
    ;;
esac
