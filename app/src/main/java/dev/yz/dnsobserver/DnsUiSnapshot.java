package dev.yz.dnsobserver;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Read-only probes run on a worker. Unknown results are never rendered as disabled. */
public final class DnsUiSnapshot {
    public String v4="unknown", v6="unknown", system="unknown", error="";
    public boolean active4, active6, serving4, serving6;
    public long sampledAt,epoch;
    public String detail4="",detail6="";
    public boolean fresh(){return sampledAt>0 && android.os.SystemClock.elapsedRealtime()-sampledAt<20000 &&
        DnsStateEpoch.valid(epoch) && serving4==DnsForwardService.isServing() && serving6==DnsIpv6GlobalController.isServing();}
    private static String reason(String rules,boolean serving,boolean active,String failure){
        if(active)return "服务与规则校验通过";
        if("unknown".equals(rules))return "Root 状态未确认";
        if(!serving)return "present".equals(rules)?"存在规则或标记，但代理未运行；请清理后重新开启":"代理和接管规则均未运行";
        if(!"present".equals(rules))return "代理在运行，但接管规则缺失";
        return failure.isEmpty()?"代理存在，但接管校验未通过":failure;
    }
    public static DnsUiSnapshot read(Context context) {
        DnsUiSnapshot result=new DnsUiSnapshot();
        result.sampledAt=android.os.SystemClock.elapsedRealtime();result.epoch=DnsStateEpoch.version();
        try {
            if(DnsStateEpoch.busy())throw new IllegalStateException("接管状态变化中，等待操作完成后重新校验");
            result.serving4=DnsForwardService.isServing();result.serving6=DnsIpv6GlobalController.isServing();
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
            if(!process.waitFor(15,TimeUnit.SECONDS)){process.destroyForcibly();throw new IllegalStateException("Root 状态读取超时");}
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
            result.active4="present".equals(result.v4) && result.serving4 && DnsRootRules.active(context);
            result.active6="present".equals(result.v6) && result.serving6 && DnsIpv6GlobalController.active(context);
            result.detail4=reason(result.v4,result.serving4,result.active4,DnsRootRules.lastCheckFailure());
            result.detail6=reason(result.v6,result.serving6,result.active6,DnsIpv6GlobalController.lastCheckFailure());
            if(!result.fresh())throw new IllegalStateException("读取期间接管状态发生变化，结果已丢弃，等待重新校验");
        }catch(Exception error){result.v4="unknown";result.v6="unknown";result.active4=false;result.active6=false;result.error=error.getMessage()==null?error.toString():error.getMessage();}
        return result;
    }
}
