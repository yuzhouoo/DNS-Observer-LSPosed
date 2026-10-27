package dev.yz.dnsobserver;

import android.content.Context;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Legacy LSPosed entry. Only System Framework / system_server is in scope.
 * Never modify DNS responses, and never perform provider IPC on a hook callback thread.
 */
public final class HookEntry implements IXposedHookLoadPackage {
    private static final String TAG = "DNSObserver: ";
    private static final AtomicBoolean INIT = new AtomicBoolean(false);

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        // Legacy framework maps system_server to "android" even when UI scope is "system".
        if (!("android".equals(lp.packageName) || "system".equals(lp.packageName))) return;
        if (lp.processName != null && !("android".equals(lp.processName)
                || "system".equals(lp.processName) || "system_server".equals(lp.processName))) return;
        if (!INIT.compareAndSet(false, true)) return;

        XposedBridge.log(TAG + "entry reached, package=" + lp.packageName
                + " process=" + lp.processName);
        // Crucial: install these independently. DNS class lookup failure must NOT disable
        // the collector heartbeat or hide the actual Hook failure.
        installContextHooks(lp.classLoader);
        installDnsHook(lp.classLoader);
    }

    private static void installContextHooks(ClassLoader loader) {
        try {
            Class<?> server = XposedHelpers.findClass("com.android.server.SystemServer", loader);
            XC_MethodHook contextHook = new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Object value = XposedHelpers.getObjectField(param.thisObject, "mSystemContext");
                        if (value instanceof Context) {
                            EventCollector.get().start((Context) value);
                        } else {
                            XposedBridge.log(TAG + "mSystemContext not available yet");
                        }
                    } catch (Throwable t) {
                        XposedBridge.log(TAG + "context init failed: " + t.getClass().getSimpleName());
                    }
                }
            };
            int count = 0;
            // Android 16 sets mSystemContext in createSystemContext; startOtherServices
            // is a later fallback for vendors that change the earlier lifecycle.
            for (String method : new String[]{"createSystemContext", "startOtherServices"}) {
                try {
                    int installed = XposedBridge.hookAllMethods(server, method, contextHook).size();
                    count += installed;
                    XposedBridge.log(TAG + "lifecycle " + method + " hooks=" + installed);
                } catch (Throwable t) {
                    XposedBridge.log(TAG + "lifecycle " + method + " failed: "
                            + t.getClass().getSimpleName());
                }
            }
            if (count == 0) XposedBridge.log(TAG + "no lifecycle hook installed");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "SystemServer class unavailable: " + t);
        }
    }

    private static void installDnsHook(ClassLoader loader) {
        try {
            Class<?> listener = XposedHelpers.findClass(
                    "com.android.server.connectivity.NetdEventListenerService", loader);
            int count = 0;
            for (Method method : listener.getDeclaredMethods()) {
                if (!"onDnsEvent".equals(method.getName())) continue;
                Class<?>[] types = method.getParameterTypes();
                if (types.length != 8 || types[0] != int.class || types[1] != int.class
                        || types[2] != int.class || types[3] != int.class
                        || types[4] != String.class || types[5] != String[].class
                        || types[6] != int.class || types[7] != int.class) continue;
                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            Object[] a = param.args;
                            EventCollector.get().accept(
                                    (Integer) a[0], (Integer) a[1], (Integer) a[2],
                                    (Integer) a[3], (String) a[4], (String[]) a[5],
                                    (Integer) a[6], (Integer) a[7]);
                        } catch (Throwable ignored) {
                            // Never disrupt Android's DNS resolver path.
                        }
                    }
                });
                count++;
            }
            if (count == 0) XposedBridge.log(TAG + "DNS signature not found (8 args required)");
            else XposedBridge.log(TAG + "system DNS hook installed: " + count);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "DNS hook unavailable: " + t);
        }
    }
}
