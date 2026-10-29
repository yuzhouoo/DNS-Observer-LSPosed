package dev.yz.dnsobserver;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Explicit Root operations; status never changes network settings. */
public final class Ipv6SystemToggle {
    private Ipv6SystemToggle() {}
    public static synchronized String set(Context context, boolean disable) throws Exception {
        return run(context, disable ? "on" : "off");
    }
    public static synchronized String status(Context context) throws Exception {
        return run(context, "status");
    }
    private static String run(Context context, String mode) throws Exception {
        String script;
        try (InputStream in = context.getAssets().open("system-ipv6.sh");
             ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096]; int count;
            while ((count = in.read(buffer)) != -1) bytes.write(buffer, 0, count);
            script = bytes.toString(StandardCharsets.UTF_8.name());
        }
        String command = "sh -c '" + script.replace("'", "'\\''") + "' -- " + mode;
        Process process = new ProcessBuilder("su", "-c", command).redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream in = process.getInputStream()) {
                byte[] buffer = new byte[1024]; int count;
                while ((count = in.read(buffer)) != -1) {
                    synchronized (output) {
                        if (output.size() < 16384)
                            output.write(buffer, 0, Math.min(count, 16384 - output.size()));
                    }
                }
            } catch (Exception ignored) { }
        }, "IPv6-root-output");
        reader.setDaemon(true); reader.start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroy();
            throw new IllegalStateException("Root 超时；操作结果未知，请刷新内核状态后重试");
        }
        reader.join(1000);
        String result;
        synchronized (output) { result = output.toString(StandardCharsets.UTF_8.name()).trim(); }
        if (process.exitValue() != 0)
            throw new IllegalStateException("Root rc=" + process.exitValue() + " " + result);
        return result;
    }
}
