#!/system/bin/sh
# DNS Observer v0.3: self-owned, removable NAT rules. NEVER flush OUTPUT or other chains.
set -u
ACTION="${1:-}"
UID_ARG="${2:-}"
PORT="${3:-}"
V6="${4:-0}"
PID_ARG="${5:-}"
TOKEN="${6:-}"
CHAIN="DOBSR53"
MARKER="/data/local/tmp/dobsr53_${UID_ARG}.run"

case "$UID_ARG" in ''|*[!0-9]*) exit 2;; esac
case "$PORT" in ''|*[!0-9]*) exit 2;; esac
case "$V6" in 0|1) ;; *) exit 2;; esac
case "$ACTION" in install|remove|watch|status) ;; *) exit 2;; esac
[ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || exit 2

IPT="$(command -v iptables 2>/dev/null || true)"
[ -n "$IPT" ] || { echo 'iptables missing' >&2; exit 3; }
IP6="$(command -v ip6tables 2>/dev/null || true)"

strip_family() {
    cmd="$1"
    [ -n "$cmd" ] || return 0
    # Remove only our two jumps, do not touch other firewall rules.
    count=0
    while "$cmd" -t nat -C OUTPUT -p udp --dport 53 -j "$CHAIN" >/dev/null 2>&1; do
        "$cmd" -t nat -D OUTPUT -p udp --dport 53 -j "$CHAIN" >/dev/null 2>&1 || break
        count=$((count+1)); [ "$count" -lt 12 ] || break
    done
    count=0
    while "$cmd" -t nat -C OUTPUT -p tcp --dport 53 -j "$CHAIN" >/dev/null 2>&1; do
        "$cmd" -t nat -D OUTPUT -p tcp --dport 53 -j "$CHAIN" >/dev/null 2>&1 || break
        count=$((count+1)); [ "$count" -lt 12 ] || break
    done
    "$cmd" -t nat -F "$CHAIN" >/dev/null 2>&1 || true
    "$cmd" -t nat -X "$CHAIN" >/dev/null 2>&1 || true
}

remove_all() {
    strip_family "$IPT"
    strip_family "$IP6"
}

prepare_family() {
    cmd="$1"
    loopback="$2"
    "$cmd" -t nat -N "$CHAIN" || return 1
    "$cmd" -t nat -A "$CHAIN" -m owner --uid-owner "$UID_ARG" -j RETURN || return 1
    "$cmd" -t nat -A "$CHAIN" -d "$loopback" -j RETURN || return 1
    "$cmd" -t nat -A "$CHAIN" -p udp -j REDIRECT --to-ports "$PORT" || return 1
    "$cmd" -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT" || return 1
    return 0
}

case "$ACTION" in
  remove)
    # Watchers exit because the marker no longer matches.
    rm -f "$MARKER"
    remove_all
    ;;
  status)
    "$IPT" -t nat -C OUTPUT -p udp --dport 53 -j "$CHAIN" >/dev/null 2>&1 &&
    "$IPT" -t nat -C OUTPUT -p tcp --dport 53 -j "$CHAIN" >/dev/null 2>&1
    ;;
  install)
    case "$PID_ARG" in ''|*[!0-9]*) exit 2;; esac
    case "$TOKEN" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
    remove_all
    rm -f "$MARKER"
    if ! prepare_family "$IPT" '127.0.0.0/8'; then remove_all; exit 4; fi
    if [ "$V6" = '1' ]; then
       if [ -z "$IP6" ] || ! prepare_family "$IP6" '::1/128'; then remove_all; exit 5; fi
    fi
    # Only expose interception once both families have been fully built.
    "$IPT" -t nat -I OUTPUT 1 -p udp --dport 53 -j "$CHAIN" || { remove_all; exit 6; }
    "$IPT" -t nat -I OUTPUT 1 -p tcp --dport 53 -j "$CHAIN" || { remove_all; exit 7; }
    if [ "$V6" = '1' ]; then
      "$IP6" -t nat -I OUTPUT 1 -p udp --dport 53 -j "$CHAIN" || { remove_all; exit 8; }
      "$IP6" -t nat -I OUTPUT 1 -p tcp --dport 53 -j "$CHAIN" || { remove_all; exit 9; }
    fi
    echo "$TOKEN" > "$MARKER" || { remove_all; exit 10; }
    chmod 600 "$MARKER" || true
    echo 'DNS redirect installed'
    ;;
  watch)
    case "$PID_ARG" in ''|*[!0-9]*) exit 2;; esac
    case "$TOKEN" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
    while :; do
        [ -f "$MARKER" ] || exit 0
        [ "$(cat "$MARKER" 2>/dev/null)" = "$TOKEN" ] || exit 0
        if ! kill -0 "$PID_ARG" 2>/dev/null; then break; fi
        # Avoid a recycled process id, and stop when the app is gone.
        case "$(tr '\000' ' ' < "/proc/$PID_ARG/cmdline" 2>/dev/null)" in
          *dev.yz.dnsobserver*) ;;
          *) break;;
        esac
        # If the user manually removed the rules, exit the watchdog.
        "$IPT" -t nat -C OUTPUT -p udp --dport 53 -j "$CHAIN" >/dev/null 2>&1 || exit 0
        sleep 5
    done
    if [ "$(cat "$MARKER" 2>/dev/null)" = "$TOKEN" ]; then
       remove_all
       rm -f "$MARKER"
    fi
    ;;
esac
