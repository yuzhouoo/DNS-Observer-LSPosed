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
case "$ACTION" in install|remove|remove-owned|watch|status|verify-clean) ;; *) exit 2;; esac
[ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || exit 2

IPT="$(command -v iptables 2>/dev/null || true)"
[ -n "$IPT" ] || { echo 'iptables missing' >&2; exit 3; }
IP6="$(command -v ip6tables 2>/dev/null || true)"

# Serialize only this module's mutations across Java callers and Root watchers.
LOCK_HOME="/data/adb/dnsobserver-v4_${UID_ARG}"
locked=0
release_lock() {
    [ "$locked" = 1 ] || return 0
    rm -f "$LOCK_HOME/lock/pid"
    rmdir "$LOCK_HOME/lock" 2>/dev/null || true
}
acquire_lock() {
    umask 077
    [ ! -L "$LOCK_HOME" ] || return 1
    mkdir -p "$LOCK_HOME" && chmod 700 "$LOCK_HOME" || return 1
    attempts=0
    while ! mkdir "$LOCK_HOME/lock" 2>/dev/null; do
        owner=$(cat "$LOCK_HOME/lock/pid" 2>/dev/null || echo 0)
        case "$owner" in ''|*[!0-9]*|0) ;; *)
            if ! kill -0 "$owner" 2>/dev/null; then
                rm -f "$LOCK_HOME/lock/pid"
                rmdir "$LOCK_HOME/lock" 2>/dev/null || true
            fi;;
        esac
        attempts=$((attempts+1)); [ "$attempts" -lt 40 ] || { echo 'ROOT_RULES_BUSY: another mutation is in progress' >&2; return 1; }
        sleep 0.1
    done
    locked=1
    trap release_lock EXIT
    trap 'exit 13' HUP INT TERM
    printf '%s\n' "$$" > "$LOCK_HOME/lock/pid" || return 1
}
owned_lines() {
    awk -v chain="$CHAIN" '
      ($1=="-N" || $1=="-A") && $2==chain {print;next}
      {for(i=1;i<NF;i++)if(($i=="-j" || $i=="-g") && $(i+1)==chain){print;break}}'
}
strip_table() {
    cmd="$1"; table="$2"
    [ -n "$cmd" ] || return 0
    # IPv6 NAT is optional; IPv6 TPROXY has its own dedicated cleanup.
    if ! "$cmd" -w 1 -t "$table" -S >/dev/null 2>&1; then
        [ "$cmd" = "$IP6" ] && return 0
        echo 'REMOVE_UNKNOWN: cannot read IPv4 firewall table' >&2; return 1
    fi
    for protocol in udp tcp; do
        count=0
        while "$cmd" -w 1 -t "$table" -C OUTPUT -p "$protocol" --dport 53 -j "$CHAIN" >/dev/null 2>&1; do
            "$cmd" -w 1 -t "$table" -D OUTPUT -p "$protocol" --dport 53 -j "$CHAIN" || return 1
            count=$((count+1)); [ "$count" -lt 32 ] || { echo REMOVE_FAILED: excessive duplicate jumps; return 1; }
        done
    done
    if "$cmd" -w 1 -t "$table" -S "$CHAIN" >/dev/null 2>&1; then
        "$cmd" -w 1 -t "$table" -F "$CHAIN" || return 1
        "$cmd" -w 1 -t "$table" -X "$CHAIN" || return 1
    fi
    remaining=$("$cmd" -w 1 -t "$table" -S) || return 1
    [ -z "$(printf '%s\n' "$remaining" | owned_lines)" ] || { echo 'REMOVE_FAILED: owned rules remain' >&2; return 1; }
}

strip_family() {
    strip_table "$1" nat || return 1
    strip_table "$1" mangle || return 1
}

remove_all() {
    result=0
    strip_family "$IPT" || result=1
    strip_family "$IP6" || result=1
    return "$result"
}

prepare_family() {
    cmd="$1"
    loopback="$2"
    "$cmd" -w 1 -t nat -N "$CHAIN" || return 1
    "$cmd" -w 1 -t nat -A "$CHAIN" -m owner --uid-owner "$UID_ARG" -j RETURN || return 1
    "$cmd" -w 1 -t nat -A "$CHAIN" -d "$loopback" -j RETURN || return 1
    "$cmd" -w 1 -t nat -A "$CHAIN" -p udp -j REDIRECT --to-ports "$PORT" || return 1
    "$cmd" -w 1 -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$PORT" || return 1
    return 0
}

guard_family() {
    cmd="$1"; loopback="$2"
    "$cmd" -w 1 -t mangle -N "$CHAIN" || return 1
    "$cmd" -w 1 -t mangle -A "$CHAIN" -m owner --uid-owner "$UID_ARG" -j RETURN || return 1
    "$cmd" -w 1 -t mangle -A "$CHAIN" -d "$loopback" -j RETURN || return 1
    for protocol in udp tcp; do
        "$cmd" -w 1 -t mangle -A "$CHAIN" -p "$protocol" -j ACCEPT || return 1
        "$cmd" -w 1 -t mangle -I OUTPUT 1 -p "$protocol" --dport 53 -j "$CHAIN" || return 1
    done
}
first_jumps() {
    "$IPT" -w 1 -t "$1" -S OUTPUT | awk '
      $1=="-A" && $2=="OUTPUT" {n++;if(n<=2 && $0 !~ /-j DOBSR53$/)bad=1} END{exit (bad || n<2)}'
}
case "$ACTION" in
  verify-clean)
    rules=$("$IPT" -w 1 -t nat -S 2>&1) || { echo "VERIFY_UNKNOWN: $rules"; exit 11; }
    mangle=$("$IPT" -w 1 -t mangle -S 2>&1) || { echo "VERIFY_UNKNOWN: $mangle"; exit 11; }
    residue=$(printf '%s\n%s\n' "$rules" "$mangle" | owned_lines)
    if [ -n "$residue" ] || [ -f "$MARKER" ]; then
        echo 'VERIFY_FAILED: IPv4 rules or marker remain'
        printf '%s\n' "$residue"
        [ ! -f "$MARKER" ] || echo 'MARKER_REMAINS: active session marker'
        exit 12
    fi
    echo VERIFY_CLEAN: IPv4 rules and marker absent
    ;;
  remove|remove-owned)
    acquire_lock || exit 13
    if [ "$ACTION" = remove-owned ] && [ -f "$MARKER" ] && [ "$(cat "$MARKER")" != "$TOKEN" ]; then
        echo 'SKIP_NEWER_SESSION: stale service cleanup left the new session intact'
        exit 0
    fi
    # Watchers exit because the marker no longer matches.
    rm -f "$MARKER" || exit 11
    remove_all || exit 12
    ;;
  status)
    first_jumps nat && first_jumps mangle || { echo 'CHECK_FAILED: DNS jumps shadowed by earlier rules'; exit 1; }
    for protocol in udp tcp; do
        "$IPT" -w 1 -t mangle -C OUTPUT -p "$protocol" --dport 53 -j "$CHAIN" >/dev/null 2>&1 &&
        "$IPT" -w 1 -t mangle -C "$CHAIN" -p "$protocol" -j ACCEPT >/dev/null 2>&1 || exit 1
    done
    "$IPT" -w 1 -t nat -C OUTPUT -p udp --dport 53 -j "$CHAIN" >/dev/null 2>&1 &&
    "$IPT" -w 1 -t nat -C OUTPUT -p tcp --dport 53 -j "$CHAIN" >/dev/null 2>&1 &&
    "$IPT" -w 1 -t nat -S "$CHAIN" >/dev/null 2>&1 &&
    [ -f "$MARKER" ]
    ;;
  install)
    case "$PID_ARG" in ''|*[!0-9]*) exit 2;; esac
    case "$TOKEN" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
    acquire_lock || exit 13
    remove_all || exit 12
    rm -f "$MARKER" || exit 11
    if ! prepare_family "$IPT" '127.0.0.0/8'; then remove_all; exit 4; fi
    if [ "$V6" = '1' ]; then
       if [ -z "$IP6" ] || ! prepare_family "$IP6" '::1/128'; then remove_all; exit 5; fi
    fi
    # Only expose interception once both families have been fully built.
    "$IPT" -w 1 -t nat -I OUTPUT 1 -p udp --dport 53 -j "$CHAIN" || { remove_all; exit 6; }
    "$IPT" -w 1 -t nat -I OUTPUT 1 -p tcp --dport 53 -j "$CHAIN" || { remove_all; exit 7; }
    if [ "$V6" = '1' ]; then
      "$IP6" -w 1 -t nat -I OUTPUT 1 -p udp --dport 53 -j "$CHAIN" || { remove_all; exit 8; }
      "$IP6" -w 1 -t nat -I OUTPUT 1 -p tcp --dport 53 -j "$CHAIN" || { remove_all; exit 9; }
    fi
    guard_family "$IPT" '127.0.0.0/8' || { remove_all; exit 10; }
    if [ "$V6" = 1 ]; then guard_family "$IP6" '::1/128' || { remove_all; exit 10; }; fi
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
        "$IPT" -w 1 -t nat -C OUTPUT -p udp --dport 53 -j "$CHAIN" >/dev/null 2>&1 || exit 0
        sleep 5
    done
    acquire_lock || exit 13
    # Recheck under the mutation lock so an old watcher cannot remove a new session.
    if [ "$(cat "$MARKER" 2>/dev/null)" = "$TOKEN" ]; then
       rm -f "$MARKER"
       remove_all || exit 12
    fi
    ;;
esac
