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
 * Legacy LSPosed entry. System Framework scope only (UI label: System Framework).
 * Does not replace any system method or alter the DNS resolution path.
 */
public final class HookEntry implements IXposedHookLoadPackage {
    private static final String TAG = "DNSObserver: ";
    private static final AtomicBoolean INIT = new AtomicBoolean(false);

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        // LSPosed legacy reports system_server as android; different forks may report system.
        if (!("android".equals(lp.packageName) || "system".equals(lp.packageName))) return;
        // Explicitly exclude system UI/application processes.
        if (lp.processName != null && !("android".equals(lp.processName)
                || "system".equals(lp.processName) || "system_server".equals(lp.processName))) return;
        if (!INIT.compareAndSet(false, true)) return;

        try {
            Class<?> listener = XposedHelpers.findClass(
                    "com.android.server.connectivity.NetdEventListenerService", lp.classLoader);
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
                        // Must never throw out of system_server / Binder listener.
                        try {
                            Object[] a = param.args;
                            EventCollector.get().accept(
                                    (Integer) a[0], (Integer) a[1], (Integer) a[2],
                                    (Integer) a[3], (String) a[4], (String[]) a[5],
                                    (Integer) a[6], (Integer) a[7]);
                        } catch (Throwable ignored) { }
                    }
                });
                count++;
            }
            if (count == 0) throw new IllegalStateException("onDnsEvent signature not found");
            Class<?> server = XposedHelpers.findClass("com.android.server.SystemServer", lp.classLoader);
            XC_MethodHook contextHook = new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Object value = XposedHelpers.getObjectField(param.thisObject, "mSystemContext");
                        if (value instanceof Context) EventCollector.get().start((Context) value);
                    } catch (Throwable t) {
                        XposedBridge.log(TAG + "context init: " + t.getClass().getSimpleName());
                    }
                }
            };
            int bootHooks = XposedBridge.hookAllMethods(server, "startBootstrapServices", contextHook).size();
            bootHooks += XposedBridge.hookAllMethods(server, "startOtherServices", contextHook).size();
            if (bootHooks == 0) XposedBridge.log(TAG + "SystemServer lifecycle hook unavailable");

            XposedBridge.log(TAG + "system DNS hook installed: " + count);
        } catch (Throwable t) {
            // No attempt to install risky hooks on alternative system paths.
            XposedBridge.log(TAG + "DNS hook unavailable: " + t);
        }
    }
}
