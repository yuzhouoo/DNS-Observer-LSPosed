#!/system/bin/sh
# DNS Observer 0.5.2: ISOLATED IPv6 TPROXY experiment, NOT a DNS 53 interceptor.
# Changes only our chain DO6TST53 and two narrow loopback/15453 PREROUTING jumps.
# Never changes routing tables, Android fwmarks, OUTPUT, or system chains.
set -u
MODE="${1:-}"; UID_ARG="${2:-}"; TOKEN="${3:-}"
CHAIN="DO6TST53"
MARKER="/data/local/tmp/dobs6t_${UID_ARG}.run"
case "$MODE" in install|recover|status|watch) ;; *) exit 2;; esac
case "$UID_ARG" in ''|*[!0-9]*) exit 2;; esac
case "$TOKEN" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
IP6="$(command -v ip6tables 2>/dev/null || true)"
[ -n "$IP6" ] || { echo 'ip6tables missing' >&2; exit 3; }
cleanup() {
    # Only remove our exact two narrow jumps. NEVER flush mangle PREROUTING.
    for proto in udp tcp; do
        n=0
        while "$IP6" -t mangle -C PREROUTING -i lo -d ::1/128 -p "$proto" --dport 15453 -j "$CHAIN" >/dev/null 2>&1; do
            "$IP6" -t mangle -D PREROUTING -i lo -d ::1/128 -p "$proto" --dport 15453 -j "$CHAIN" >/dev/null 2>&1 || break
            n=$((n+1)); [ "$n" -lt 8 ] || break
        done
    done
    "$IP6" -t mangle -F "$CHAIN" >/dev/null 2>&1 || true
    "$IP6" -t mangle -X "$CHAIN" >/dev/null 2>&1 || true
}
case "$MODE" in
  recover)
    rm -f "$MARKER"
    cleanup
    echo 'RECOVERED: isolated IPv6 test rules removed (no route change)'
    ;;
  status)
    "$IP6" -t mangle -L "$CHAIN" -n -v -x 2>&1
    ;;
  install)
    # Do not overwrite another session; an App crash may leave the prior session
    # while its watchdog is running. The user can hit explicit recovery first.
    if [ -f "$MARKER" ]; then echo 'test already active; press recover first' >&2; exit 4; fi
    if "$IP6" -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        echo 'test chain already present; press recover first' >&2; exit 4
    fi
    "$IP6" -t mangle -N "$CHAIN" || exit 5
    # No broad :53 interception. These rules are only for locally generated
    # loopback ::1:15453 synthetic packets. The mark has no routing rule.
    "$IP6" -t mangle -A "$CHAIN" -p udp -j TPROXY --on-ip ::1 --on-port 15454 --tproxy-mark 0x20000000/0x20000000 || { cleanup; exit 6; }
    "$IP6" -t mangle -A "$CHAIN" -p tcp -j TPROXY --on-ip ::1 --on-port 15454 --tproxy-mark 0x20000000/0x20000000 || { cleanup; exit 7; }
    "$IP6" -t mangle -I PREROUTING 1 -i lo -d ::1/128 -p udp --dport 15453 -j "$CHAIN" || { cleanup; exit 8; }
    "$IP6" -t mangle -I PREROUTING 1 -i lo -d ::1/128 -p tcp --dport 15453 -j "$CHAIN" || { cleanup; exit 9; }
    if ! echo "$TOKEN" > "$MARKER"; then cleanup; exit 10; fi
    chmod 600 "$MARKER" || true
    # Launch the independent watchdog BEFORE returning to the caller.
    # Survives even if the app is killed right after this script exits.
    /system/bin/sh "$0" watch "$UID_ARG" "$TOKEN" </dev/null >/dev/null 2>&1 &
    echo 'INSTALLED: IPv6 TPROXY loopback probe only, TTL 20s'
    ;;
  watch)
    # Root watchdog, independent of App lifecycle. No app PID required.
    n=0
    while [ "$n" -lt 20 ]; do
        [ "$(cat "$MARKER" 2>/dev/null)" = "$TOKEN" ] || exit 0
        sleep 1
        n=$((n+1))
    done
    if [ "$(cat "$MARKER" 2>/dev/null)" = "$TOKEN" ]; then
        rm -f "$MARKER"
        cleanup
    fi
    ;;
esac
