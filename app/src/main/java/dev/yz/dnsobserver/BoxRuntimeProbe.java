package dev.yz.dnsobserver;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Bounded read-only root probe. Never execute or source third-party settings. */
public final class BoxRuntimeProbe {
    public String state="unknown",signature="",error="";
    public static BoxRuntimeProbe read(Context context) {
        BoxRuntimeProbe result=new BoxRuntimeProbe();
        try {
            File script=RootScriptFiles.install(context,"dns-box-status.sh","dns-box-status.sh");
            String command="/system/bin/sh '"+script.getAbsolutePath().replace("'","'\\''")+"'";
            Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();
            Thread reader=new Thread(()->{
                try(InputStream in=process.getInputStream()) {
                    byte[] b=new byte[1024];int n;
                    while((n=in.read(b))!=-1)synchronized(bytes){if(bytes.size()<16384)bytes.write(b,0,n);}
                }catch(Exception ignored) { }
            },"DNS-Box-probe-output");
            reader.setDaemon(true);reader.start();
            if(!process.waitFor(10,TimeUnit.SECONDS)){process.destroyForcibly();throw new IllegalStateException("Root 状态读取超时");}
            reader.join(500);
            if(process.exitValue()!=0)throw new IllegalStateException("Root 探测失败 rc="+process.exitValue());
            String text;synchronized(bytes){text=bytes.toString(StandardCharsets.UTF_8.name());}
            for(String line:text.split("\\n")) {
                if(line.startsWith("BOX="))result.state=line.substring(4).trim();
                if(line.startsWith("SIGNATURE="))result.signature=line.substring(10).trim();
            }
            if(result.signature.isEmpty())throw new IllegalStateException("Box 探测输出不完整");
        }catch(Exception ex){result.state="unknown";result.signature="";result.error=ex.toString();}
        return result;
    }
}
