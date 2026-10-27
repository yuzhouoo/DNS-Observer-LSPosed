package de.robv.android.xposed;
public final class XposedHelpers {
    private XposedHelpers() { }
    public static Class<?> findClass(String name, ClassLoader loader) {
        throw new UnsupportedOperationException("compile only");
    }
    public static Object getObjectField(Object value, String name) {
        throw new UnsupportedOperationException("compile only");
    }
}
