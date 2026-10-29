package dev.yz.dnsobserver;

import android.content.Context;
import android.os.Process;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** The ONLY code responsible for Root firewall changes. No persistent boot scripts. */
public final class DnsRootRules {
    public static final int PORT = 15353;
    private static final String SCRIPT = "dns-root-v062.sh";

    private DnsRootRules() { }

    private static File script(Context context) throws Exception {
        return RootScriptFiles.install(context,"dns-root.sh",SCRIPT);
    }

    private static String path(File file) {
        String value = file.getAbsolutePath();
        if (!value.matches("/[a-zA-Z0-9_./-]+")) throw new IllegalArgumentException("unsafe script path");
        return value;
    }

    private static String invoke(Context ctx, String mode, boolean ipv6, String token, int timeout) throws Exception {
        String file = path(script(ctx));
        int uid = Process.myUid();
        int pid = Process.myPid();
        if (!mode.matches("install|remove|watch|status|verify-clean") || !token.matches("[a-zA-Z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("invalid command arguments");
        }
        String cmd = "/system/bin/sh " + file + " " + mode + " " + uid + " "
                + PORT + " " + (ipv6 ? "1" : "0") + " " + pid + " " + token;
        if ("watch".equals(mode)) cmd += " </dev/null >/dev/null 2>&1 &";
        java.lang.Process proc = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread drain = new Thread(() -> {
            try (InputStream in = proc.getInputStream()) {
                byte[] b = new byte[1024];
                int n;
                while ((n = in.read(b)) != -1) {
                    synchronized (output) { if (output.size() < 8192) output.write(b, 0, n); }
                }
            } catch (Exception ignored) { }
        }, "DnsSuOutput");
        drain.setDaemon(true);
        drain.start();
        if (!proc.waitFor(timeout, TimeUnit.SECONDS)) {
            proc.destroyForcibly();
            throw new IllegalStateException("Root 命令超时: " + mode);
        }
        drain.join(300);
        if (proc.exitValue() != 0) {
            throw new IllegalStateException("Root " + mode + " 失败 (" + proc.exitValue() + "): "
                    + new String(output.toByteArray(), StandardCharsets.UTF_8).trim());
        }
        return new String(output.toByteArray(), StandardCharsets.UTF_8).trim();
    }

    public static void install(Context ctx, boolean ipv6, String token) throws Exception {
        try {
            invoke(ctx, "install", ipv6, token, 15);
            invoke(ctx, "watch", ipv6, token, 8);
        } catch (Exception e) {
            try { remove(ctx); } catch (Exception ignored) { }
            throw e;
        }
    }

    public static void remove(Context ctx) throws Exception {
        invoke(ctx, "remove", false, "cleanup", 12);
    }

    /** An IPv6 NAT table is required for the existing REDIRECT implementation. */
    public static boolean supportsIpv6Nat(Context ctx) {
        try {
            java.lang.Process proc = new ProcessBuilder("su", "-c",
                    "ip6tables -t nat -S >/dev/null 2>&1").start();
            if (!proc.waitFor(5, TimeUnit.SECONDS)) {
                proc.destroyForcibly();return false;
            }
            return proc.exitValue() == 0;
        } catch (Exception e) { return false; }
    }

    public static boolean clean(Context ctx) throws Exception {
        return invoke(ctx,"verify-clean",false,"cleanup",6).contains("VERIFY_CLEAN");
    }

    public static boolean active(Context ctx) {
        try { invoke(ctx, "status", false, "status", 5); return true; }
        catch (Exception ignored) { return false; }
    }
}
