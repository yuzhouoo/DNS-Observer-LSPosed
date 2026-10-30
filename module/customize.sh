#!/system/bin/sh
SKIPMOUNT=true
ui_print "域瞳后台：不包含 Mihomo 核心，不修改系统分区。"
[ "$ARCH" = arm64 ] || abort "当前运行包仅支持 arm64"
set_perm_recursive "$MODPATH" 0 0 0700 0600
set_perm "$MODPATH/bin/yutong" 0 0 0700
set_perm "$MODPATH/action.sh" 0 0 0700
set_perm "$MODPATH/service.sh" 0 0 0700
set_perm "$MODPATH/boot-completed.sh" 0 0 0700
ui_print "初次安装默认全部停止；请在 APK 三模式控制台配置。"
