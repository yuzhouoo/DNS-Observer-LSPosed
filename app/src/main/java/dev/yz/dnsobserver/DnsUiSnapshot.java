package dev.yz.dnsobserver;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Read-only probes run on a worker. Unknown results are never rendered as disabled. */
public final class DnsUiSnapshot {
    public String v4="unknown", v6="unknown", system="unknown", error="";
    public boolean active4, active6;
    public static DnsUiSnapshot read(Context context) {
        DnsUiSnapshot result=new DnsUiSnapshot();
        try {
            String script;
            try(InputStream in=context.getAssets().open("dns-ui-status.sh");
                ByteArrayOutputStream bytes=new ByteArrayOutputStream()) {
                byte[] b=new byte[4096];int n;
                while((n=in.read(b))!=-1)bytes.write(b,0,n);
                script=bytes.toString(StandardCharsets.UTF_8.name());
            }
            String command="sh -c '"+script.replace("'","'\\''")+"' -- "+android.os.Process.myUid();
            Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
            ByteArrayOutputStream output=new ByteArrayOutputStream();
            Thread drain=new Thread(()->{
                try(InputStream in=process.getInputStream()) {
                    byte[] b=new byte[1024];int n;
                    while((n=in.read(b))!=-1)synchronized(output){if(output.size()<8192)output.write(b,0,n);}
                }catch(Exception ignored) { }
            },"DNS-status-output");
            drain.setDaemon(true);drain.start();
            if(!process.waitFor(15,TimeUnit.SECONDS)){process.destroy();throw new IllegalStateException("Root 状态读取超时");}
            drain.join(500);
            if(process.exitValue()!=0)throw new IllegalStateException("Root 未授权或状态读取失败");
            String text;
            synchronized(output){text=output.toString(StandardCharsets.UTF_8.name());}
            for(String line:text.split("\\n")) {
                if(line.startsWith("V4="))result.v4=line.substring(3).trim();
                if(line.startsWith("V6="))result.v6=line.substring(3).trim();
                if(line.startsWith("SYSTEM="))result.system=line.substring(7).trim();
            }
            // A rule alone is insufficient: the actual serving process must also be alive.
            result.active4="present".equals(result.v4) && DnsForwardService.isServing() && DnsRootRules.active(context);
            result.active6="present".equals(result.v6) && DnsIpv6GlobalController.isServing() && DnsIpv6GlobalController.active(context);
        }catch(Exception error){result.error=error.getMessage()==null?error.toString():error.getMessage();}
        return result;
    }
}
