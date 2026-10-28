#!/system/bin/sh
# v0.5.5 ONLY: exact UDP/TCP synthetic ports, ::1 or documentation IPv6 address.
# Independent watchdog; never edits existing Android tables/chains/fwmarks.
set -u
MODE="${1:-}"; UID_ARG="${2:-}"; TOKEN="${3:-}"
CHAIN=DO6TST55
LOOP='::1/128'; TEST_ADDR='2001:db8:ffff::53/128'; TEST_IP='2001:db8:ffff::53'
PORT=15453; PROXY=15454; TABLE=19753; PREF=15000; MARK='0x20000000/0x20000000'
MARKER="/data/local/tmp/dobs6t55_${UID_ARG}.run"
case "$MODE" in install-loop|install-local|recover|status|watch) ;; *) exit 2;; esac
case "$UID_ARG" in ''|*[!0-9]*) exit 2;; esac
case "$TOKEN" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
IP6="$(command -v ip6tables 2>/dev/null || true)"
IP="$(command -v ip 2>/dev/null || true)"
[ -n "$IP6" ] && [ -n "$IP" ] || { echo 'missing ip6tables/ip' >&2; exit 3; }
# A marker/chain is proof that THIS module owns reserved route and rule ids.
owned() {
    [ -f "$MARKER" ] || "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1
}
remove_jumps() {
    for proto in udp tcp; do
        for addr in "$LOOP" "$TEST_ADDR"; do
            n=0
            while "$IP6" -t mangle -C PREROUTING -i lo -d "$addr" -p "$proto" --dport "$PORT" -j "$CHAIN" >/dev/null 2>&1; do
                "$IP6" -t mangle -D PREROUTING -i lo -d "$addr" -p "$proto" --dport "$PORT" -j "$CHAIN" >/dev/null 2>&1 || break
                n=$((n+1)); [ "$n" -lt 8 ] || break
            done
        done
        n=0
        while "$IP6" -t mangle -C OUTPUT -d "$TEST_ADDR" -p "$proto" --dport "$PORT" -m owner --uid-owner "$UID_ARG" -j MARK --set-xmark "$MARK" >/dev/null 2>&1; do
            "$IP6" -t mangle -D OUTPUT -d "$TEST_ADDR" -p "$proto" --dport "$PORT" -m owner --uid-owner "$UID_ARG" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 || break
            n=$((n+1)); [ "$n" -lt 8 ] || break
        done
    done
}
rule_present() {
    "$IP" -6 rule show 2>/dev/null | grep -Eq '(^| )15000:.*fwmark 0x20000000/0x20000000.*lookup 19753( |$)'
}
route_present() {
    "$IP" -6 route show table "$TABLE" 2>/dev/null | grep -Fq "local $TEST_IP "
}
clear_owned() {
    owned || return 0
    remove_jumps
    "$IP6" -t mangle -F "$CHAIN" >/dev/null 2>&1 || true
    "$IP6" -t mangle -X "$CHAIN" >/dev/null 2>&1 || true
    if rule_present; then "$IP" -6 rule del pref "$PREF" fwmark "$MARK" lookup "$TABLE" >/dev/null 2>&1 || true; fi
    if route_present; then "$IP" -6 route del local "$TEST_ADDR" dev lo table "$TABLE" >/dev/null 2>&1 || true; fi
}
verify_clean() {
    problem=0
    "$IP6" -t mangle -L PREROUTING -n >/dev/null 2>&1 || problem=1
    "$IP6" -t mangle -L OUTPUT -n >/dev/null 2>&1 || problem=1
    "$IP" -6 rule show >/dev/null 2>&1 || problem=1
    for proto in udp tcp; do
        for addr in "$LOOP" "$TEST_ADDR"; do
            "$IP6" -t mangle -C PREROUTING -i lo -d "$addr" -p "$proto" --dport "$PORT" -j "$CHAIN" >/dev/null 2>&1 && problem=1
        done
        "$IP6" -t mangle -C OUTPUT -d "$TEST_ADDR" -p "$proto" --dport "$PORT" -m owner --uid-owner "$UID_ARG" -j MARK --set-xmark "$MARK" >/dev/null 2>&1 && problem=1
    done
    "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1 && problem=1
    rule_present && problem=1
    route_present && problem=1
    if [ "$problem" -eq 0 ]; then echo 'VERIFY_CLEAN: no module firewall/rule/route residue'; return 0; fi
    echo 'VERIFY_FAILED: module test chain/rule/route remains; manual recovery needed' >&2
    return 1
}
case "$MODE" in
 recover)
    clear_owned
    if verify_clean; then rm -f "$MARKER"; echo 'RECOVERED: verified clean'; else exit 11; fi
    ;;
 status)
    echo 'PREROUTING/OUTPUT test rules:'
    "$IP6" -t mangle -L PREROUTING -n -v -x 2>&1 | grep "$CHAIN" || true
    "$IP6" -t mangle -L OUTPUT -n -v -x 2>&1 | grep "$TEST_IP" || true
    echo 'TPROXY target:'
    "$IP6" -t mangle -L "$CHAIN" -n -v -x 2>&1 || true
    echo 'Test policy rule:'
    "$IP" -6 rule show | grep '15000:' || true
    echo 'Test route:'
    "$IP" -6 route show table "$TABLE" 2>&1
    ;;
 install-loop|install-local)
    if [ -f "$MARKER" ] || "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        echo 'PRECHECK_FAILED: prior session remains; click recover' >&2; exit 4
    fi
    # Existing routing entries must NOT be overwritten or deleted, even if same priority.
    if "$IP" -6 rule show | grep -Eq '^[[:space:]]*15000:'; then echo 'PRECHECK_FAILED: rule priority 15000 in use' >&2; exit 4; fi
    if [ -n "$("$IP" -6 route show table "$TABLE" 2>/dev/null)" ]; then echo 'PRECHECK_FAILED: route table 19753 in use' >&2; exit 4; fi
    if [ "$MODE" = install-local ]; then
        if ! "$IP6" -t mangle -m owner -h >/dev/null 2>&1; then echo 'PRECHECK_FAILED: owner match unavailable' >&2; exit 4; fi
    fi
    printf '%s\n' "$TOKEN" > "$MARKER" || exit 5
    chmod 600 "$MARKER" || true
    # Watchdog begins BEFORE firewall or routing changes.
    /system/bin/sh "$0" watch "$UID_ARG" "$TOKEN" </dev/null >/dev/null 2>&1 &
    "$IP6" -t mangle -N "$CHAIN" || { clear_owned; exit 5; }
    for proto in udp tcp; do
        "$IP6" -t mangle -A "$CHAIN" -p "$proto" -j TPROXY --on-ip ::1 --on-port "$PROXY" --tproxy-mark "$MARK" || { clear_owned; exit 6; }
    done
    if [ "$MODE" = install-local ]; then
        # Highly scoped: only this App UID, exact documentation address and test port.
        "$IP" -6 route add local "$TEST_ADDR" dev lo table "$TABLE" || { clear_owned; exit 7; }
        "$IP" -6 rule add pref "$PREF" fwmark "$MARK" lookup "$TABLE" || { clear_owned; exit 8; }
        for proto in udp tcp; do
            "$IP6" -t mangle -I OUTPUT 1 -d "$TEST_ADDR" -p "$proto" --dport "$PORT" -m owner --uid-owner "$UID_ARG" -j MARK --set-xmark "$MARK" || { clear_owned; exit 9; }
            "$IP6" -t mangle -I PREROUTING 1 -i lo -d "$TEST_ADDR" -p "$proto" --dport "$PORT" -j "$CHAIN" || { clear_owned; exit 10; }
        done
    else
        for proto in udp tcp; do
            "$IP6" -t mangle -I PREROUTING 1 -i lo -d "$LOOP" -p "$proto" --dport "$PORT" -j "$CHAIN" || { clear_owned; exit 10; }
        done
    fi
    echo "INSTALLED: $MODE scoped TPROXY, watchdog 35s"
    ;;
 watch)
    n=0
    while [ "$n" -lt 35 ]; do
        [ "$(cat "$MARKER" 2>/dev/null)" = "$TOKEN" ] || exit 0
        sleep 1; n=$((n+1))
    done
    if [ "$(cat "$MARKER" 2>/dev/null)" = "$TOKEN" ]; then
        clear_owned
        if verify_clean; then rm -f "$MARKER"; fi
    fi
    ;;
esac
