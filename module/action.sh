#!/system/bin/sh
# The module-local binary also works before its first boot deployment.
MODDIR=${0%/*}
"$MODDIR/bin/yutong" restore-app
"$MODDIR/bin/yutong" status
