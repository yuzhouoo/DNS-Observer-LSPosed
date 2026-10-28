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
        while "$IP6" -t mangle -C PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1; do
            "$IP6" -t mangle -D PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 || break
            n=$((n+1)); [ "$n" -lt 8 ] || break
        done
        for subnet in '2000::/3' 'fc00::/7'; do
            n=0
            while "$IP6" -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1; do
                "$IP6" -t mangle -D OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || break
                n=$((n+1)); [ "$n" -lt 8 ] || break
            done
            n=0
            while "$IP6" -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1; do
                "$IP6" -t mangle -D OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || break
                n=$((n+1)); [ "$n" -lt 8 ] || break
            done
        done
    done
}
owned() {
    [ -f "$MARKER" ] || "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1 ||
    "$IP6" -t mangle -C PREROUTING -i lo -p udp --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 ||
    "$IP6" -t mangle -C PREROUTING -i lo -p tcp --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1
}
route_present() { "$IP" -6 route show table "$TABLE" 2>/dev/null | grep -Eq '^local ::/0 dev lo([[:space:]]|$)'; }
rule_present() { "$IP" -6 rule show 2>/dev/null | grep -Eq '(^|[[:space:]])15010:.*fwmark 0x40000000/0x40000000.*lookup 19754([[:space:]]|$)'; }
clear_owned() {
    owned || return 0
    del_jumps
    "$IP6" -t mangle -F "$CHAIN" >/dev/null 2>&1 || true
    "$IP6" -t mangle -X "$CHAIN" >/dev/null 2>&1 || true
    if rule_present; then "$IP" -6 rule del pref "$PREF" fwmark "$MARK" lookup "$TABLE" >/dev/null 2>&1 || true; fi
    if route_present; then "$IP" -6 route del local ::/0 dev lo table "$TABLE" >/dev/null 2>&1 || true; fi
}
verify_clean() {
    bad=0
    "$IP6" -t mangle -L PREROUTING -n >/dev/null 2>&1 || bad=1
    "$IP6" -t mangle -L OUTPUT -n >/dev/null 2>&1 || bad=1
    "$IP" -6 rule show >/dev/null 2>&1 || bad=1
    for proto in udp tcp; do
        "$IP6" -t mangle -C PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 && bad=1
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 && bad=1
            "$IP6" -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1 && bad=1
        done
    done
    "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1 && bad=1
    rule_present && bad=1
    route_present && bad=1
    if [ "$bad" -eq 0 ]; then echo 'VERIFY_CLEAN: global module rules and routes absent'; return 0; fi
    echo 'VERIFY_FAILED: global module residue; manual cleanup required' >&2; return 1
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
    if verify_clean; then rm -f "$MARKER"; echo 'RECOVERED: verified clean'; else exit 11; fi
    ;;
 check)
    [ "$(cat "$MARKER" 2>/dev/null)" = "global:$TOKEN" ] || exit 1
    "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1 || exit 1
    rule_present && route_present || exit 1
    for proto in udp tcp; do
        "$IP6" -t mangle -C PREROUTING -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" >/dev/null 2>&1 || exit 1
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || exit 1
        done
    done
    echo 'ACTIVE: IPv6 TPROXY selectors complete'
    ;;
 status)
    echo 'OUTPUT/PREROUTING:'
    "$IP6" -t mangle -L OUTPUT -n -v -x 2>&1 | grep -E '2000::/3|fc00::/7' || true
    "$IP6" -t mangle -L PREROUTING -n -v -x 2>&1 | grep "$CHAIN" || true
    "$IP6" -t mangle -L "$CHAIN" -n -v -x 2>&1 || true
    "$IP" -6 rule show | grep '15010:' || true
    "$IP" -6 route show table "$TABLE" 2>&1
    ;;
 install-probe)
    # Never accept an existing marker, table, chain, pref or pre-used fwmark.
    if "$IP6" -t mangle -S DO6TST55 >/dev/null 2>&1; then
        echo 'PRECHECK_FAILED: legacy IPv6 pilot chain present; recover pilot first' >&2; exit 4
    fi
    if [ -f "$MARKER" ] || "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        echo 'PRECHECK_FAILED: previous global test exists' >&2; exit 4
    fi
    if "$IP" -6 rule show | grep -Eq '^[[:space:]]*15010:' ||
       [ -n "$("$IP" -6 route show table "$TABLE" 2>/dev/null)" ]; then
        echo 'PRECHECK_FAILED: reserved route/pref occupied (15010 / table 19754)' >&2
        "$IP" -6 rule show | grep '15010:' >&2 || true
        "$IP" -6 route show table "$TABLE" >&2 || true
        exit 4
    fi
    if "$IP6" -t mangle -S 2>/dev/null | grep -q '0x40000000'; then
        echo 'PRECHECK_FAILED: reserved mark already used' >&2; exit 4
    fi
    "$IP6" -t mangle -m owner -h >/dev/null 2>&1 || { echo 'PRECHECK_FAILED: owner match unavailable' >&2; exit 4; }
    "$IP6" -t mangle -j TPROXY -h >/dev/null 2>&1 || { echo 'PRECHECK_FAILED: TPROXY missing' >&2; exit 4; }
    printf 'probe:%s\n' "$TOKEN" > "$MARKER" || exit 5
    chmod 600 "$MARKER" || true
    # Crash-only guard, NO periodic expiration. This guard releases stale rules
    # only when the owning Android process disappears, never after a TTL.
    case "$OWNER_PID" in ''|*[!0-9]*) echo 'PRECHECK_FAILED: missing owner PID' >&2; rm -f "$MARKER"; exit 4;; esac
    /system/bin/sh "$0" watch "$APP_UID" "$TOKEN" "$OWNER_PID" </dev/null >/dev/null 2>&1 &
    "$IP6" -t mangle -N "$CHAIN" || { clear_owned; exit 5; }
    for proto in udp tcp; do
        "$IP6" -t mangle -A "$CHAIN" -p "$proto" -j TPROXY --on-ip ::1 --on-port "$PROXY" --tproxy-mark "$MARK" || { clear_owned; exit 6; }
    done
    "$IP" -6 route add local ::/0 dev lo table "$TABLE" || { clear_owned; exit 7; }
    "$IP" -6 rule add pref "$PREF" fwmark "$MARK" lookup "$TABLE" || { clear_owned; exit 8; }
    for proto in udp tcp; do
        "$IP6" -t mangle -I PREROUTING 1 -i lo -p "$proto" --dport 53 -m mark --mark "$MARK" -j "$CHAIN" || { clear_owned; exit 9; }
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -t mangle -I OUTPUT 1 -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" || { clear_owned; exit 10; }
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
            "$IP6" -t mangle -C OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || { echo 'PRECHECK_FAILED: selftest rule missing' >&2; exit 4; }
        done
    done
    # Add broad rule only on explicit user opt-in AFTER successful selftest.
    # Root UID 0 excluded to prevent DNS forwarding recursion.
    for proto in udp tcp; do
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -t mangle -I OUTPUT 1 -d "$subnet" -p "$proto" --dport 53 -m owner ! --uid-owner 0 -j MARK --set-xmark "$MARK" || { clear_owned; exit 10; }
        done
    done
    for proto in udp tcp; do
        for subnet in '2000::/3' 'fc00::/7'; do
            "$IP6" -t mangle -D OUTPUT -d "$subnet" -p "$proto" --dport 53 -m owner --uid-owner "$APP_UID" -j MARK --set-xmark "$MARK" || { clear_owned; exit 11; }
        done
    done
    printf 'global:%s\n' "$TOKEN" > "$MARKER" || { clear_owned; exit 12; }
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
        if verify_clean; then rm -f "$MARKER"; fi
    fi
    ;;
esac
