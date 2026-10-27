package de.robv.android.xposed;
import java.lang.reflect.Member;
import java.util.Set;
public final class XposedBridge {
    private XposedBridge() { }
    public static Set<XC_MethodHook.Unhook> hookAllMethods(Class<?> c, String name, XC_MethodHook hook) {
        throw new UnsupportedOperationException("compile only");
    }
    public static XC_MethodHook.Unhook hookMethod(Member m, XC_MethodHook hook) {
        throw new UnsupportedOperationException("compile only");
    }
    public static void log(String message) { throw new UnsupportedOperationException("compile only"); }
}
