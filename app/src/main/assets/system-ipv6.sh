#!/system/bin/sh
# Snapshot and restore only disable_ipv6. Never alter DNS takeover rules.
set -u
dir=/proc/sys/net/ipv6/conf
home=/data/adb/dnsobserver-ipv6
boot_file=/proc/sys/kernel/random/boot_id
mode=${1:-status}
[ -d "$dir" ] || { echo IPV6_UNAVAILABLE; exit 2; }
snapshot() {
    for f in "$dir"/*/disable_ipv6; do
        [ -f "$f" ] || continue
        value=$(cat "$f") || return 1
        case "$value" in 0|1) ;; *) return 1;; esac
        name=${f%/disable_ipv6}; name=${name##*/}
        printf '%s %s\n' "$name" "$value" || return 1
    done
}
validate() {
    [ -s "$1" ] || return 1
    while read -r name value extra; do
        case "$name" in ''|*[!a-zA-Z0-9_.:-]*) return 1;; esac
        case "$value" in 0|1) ;; *) return 1;; esac
        [ -z "$extra" ] || return 1
    done < "$1"
    awk '$1=="all" {a++} $1=="default" {d++} END {exit !(a==1 && d==1)}' "$1"
}
write_value() {
    [ -f "$dir/$1/disable_ipv6" ] || return 0
    printf '%s\n' "$2" > "$dir/$1/disable_ipv6" || return 1
}
restore() {
    validate "$1" || return 1
    # all may modify individual interfaces: restore it before their own values.
    for special in all default; do
        value=$(awk -v key="$special" '$1==key {print $2}' "$1")
        write_value "$special" "$value" || return 1
    done
    fallback=$(awk '$1=="default" {print $2}' "$1")
    for f in "$dir"/*/disable_ipv6; do
        [ -f "$f" ] || continue
        name=${f%/disable_ipv6}; name=${name##*/}
        case "$name" in all|default) continue;; esac
        value=$(awk -v key="$name" '$1==key {print $2}' "$1")
        write_value "$name" "${value:-$fallback}" || return 1
    done
}
verify() {
    fallback=$(awk '$1=="default" {print $2}' "$1")
    for f in "$dir"/*/disable_ipv6; do
        [ -f "$f" ] || continue
        name=${f%/disable_ipv6}; name=${name##*/}
        value=$(awk -v key="$name" '$1==key {print $2}' "$1")
        [ "$(cat "$f")" = "${value:-$fallback}" ] || return 1
    done
}
report() {
    values=$(snapshot) || { echo IPV6_STATUS_UNKNOWN; return 1; }
    [ -n "$values" ] || { echo IPV6_STATUS_UNKNOWN; return 1; }
    if printf '%s\n' "$values" | awk '$2!=1 {exit 1}'; then
        echo IPV6_DISABLED
    else
        echo IPV6_NOT_FULLY_DISABLED
    fi
    printf '%s\n' "$values"
}
case "$mode" in status) report; exit $?;; on|off) ;; *) exit 7;; esac
umask 077
[ ! -L "$home" ] || exit 8
mkdir -p "$home" && chmod 700 "$home" || exit 8
# Recover a lock left by a previous boot or a dead shell, but never overlap a live operation.
if ! mkdir "$home/lock" 2>/dev/null; then
    owner=$(cat "$home/lock/pid" 2>/dev/null || echo 0)
    case "$owner" in ''|*[!0-9]*|0) echo IPV6_BUSY; exit 8;; esac
    kill -0 "$owner" 2>/dev/null && { echo IPV6_BUSY; exit 8; }
    rm -f "$home/lock/pid"
    rmdir "$home/lock" && mkdir "$home/lock" || exit 8
fi
printf '%s\n' "$$" > "$home/lock/pid" || exit 8
state=$home/original
before=$home/before
active=0
finish() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$active" = 1 ]; then
        if restore "$before" && verify "$before"; then
            echo ROLLBACK_OK
        else
            echo ROLLBACK_FAILED_SNAPSHOT_RETAINED
            rc=9
        fi
    fi
    rm -f "$home/target" "$home/lock/pid"
    rmdir "$home/lock"
    exit "$rc"
}
trap finish EXIT
trap 'exit 10' HUP INT TERM
boot=$(cat "$boot_file") || exit 2
if [ -f "$home/boot" ] && [ "$(cat "$home/boot")" != "$boot" ]; then
    rm -f "$state" "$before" || exit 2
fi
printf '%s\n' "$boot" > "$home/boot" || exit 2
snapshot > "$before" && validate "$before" || exit 2
if [ "$mode" = on ]; then
    if [ ! -f "$state" ]; then
        cp "$before" "$home/original.tmp" && mv "$home/original.tmp" "$state" || exit 2
    fi
    validate "$state" || exit 2
    awk '{print $1, 1}' "$before" > "$home/target" || exit 2
    target=$home/target
else
    if [ ! -f "$state" ]; then
        echo NO_SAVED_STATE
        report
        exit 4
    fi
    validate "$state" || exit 2
    target=$state
fi
active=1
restore "$target" && verify "$target" || { echo APPLY_FAILED; exit 3; }
if [ "$mode" = off ]; then
    rm -f "$state" || exit 3
    echo IPV6_RESTORED
fi
active=0
report
