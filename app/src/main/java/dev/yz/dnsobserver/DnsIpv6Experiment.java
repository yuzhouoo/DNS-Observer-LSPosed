package dev.yz.dnsobserver;

import android.content.Context;
import android.os.Process;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Isolated IPv6 loopback + synthetic locally-originated TPROXY experiment.
 * NEVER intercepts real DNS port 53. Every stage is explicitly rolled back. */
public final class DnsIpv6Experiment {
    private static final String SCRIPT_NAME="dns-ipv6-probe-v057.sh";
    private static final int TEST_PORT=15453, LISTEN_PORT=15454;
    private static final int DIRECT_TCP_PORT=15455;
    private static final String DOC_IP="2001:db8:ffff::53";
    private DnsIpv6Experiment() {}

    private static File script(Context ctx) throws Exception {
        File f=new File(ctx.getFilesDir(),SCRIPT_NAME);
        if(f.isFile()&&f.length()>400)return f;
        try(InputStream in=ctx.getAssets().open("dns-ipv6-tproxy-probe.sh");
            FileOutputStream out=new FileOutputStream(f,false)) {
            byte[] buf=new byte[4096];int n;
            while((n=in.read(buf))!=-1)out.write(buf,0,n);
            out.getFD().sync();
        }
        if(!f.setReadable(true,true)||!f.setWritable(true,true))
            throw new IllegalStateException("无法保护 IPv6 实验脚本权限");
        return f;
    }
    private static String root(Context ctx,String mode,String token,int seconds) throws Exception {
        if(!mode.matches("install-loop|install-local|install-dns|recover|status")||!token.matches("[A-Za-z0-9_-]{1,64}"))
            throw new IllegalArgumentException("Invalid experiment arguments");
        String path=script(ctx).getAbsolutePath();
        if(!path.matches("/[a-zA-Z0-9_./-]+"))throw new IllegalArgumentException("unsafe path");
        String command="/system/bin/sh "+path+" "+mode+" "+Process.myUid()+" "+token;
        java.lang.Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        ByteArrayOutputStream output=new ByteArrayOutputStream();
        Thread drain=new Thread(()->{
            try(InputStream in=process.getInputStream()){
                byte[] buf=new byte[1024];int count;
                while((count=in.read(buf))!=-1) {
                    synchronized(output){int free=16000-output.size();if(free>0)output.write(buf,0,Math.min(count,free));}
                }
            }catch(Exception ignored){}
        },"DNS-IP6-SuOutput");
        drain.setDaemon(true);drain.start();
        if(!process.waitFor(seconds,TimeUnit.SECONDS)){
            process.destroyForcibly();throw new IllegalStateException("Root "+mode+" 超时");
        }
        String result=output.toString(StandardCharsets.UTF_8.name()).trim();
        if(process.exitValue()!=0)throw new IllegalStateException("Root "+mode+" 返回码 "+process.exitValue()+": "+result);
        return result;
    }
    public static String recover(Context ctx) throws Exception {return root(ctx,"recover","cleanup",12);}
    private static String quote(String text){return "'"+text.replace("'","'\\''")+"'";}
    private static java.lang.Process listener(Context ctx,String token,String proto,String stage,BlockingQueue<String> logs) throws Exception {
        String apk=ctx.getApplicationInfo().sourceDir;
        if(apk==null||!apk.startsWith("/data/app/")||!new File(apk).isFile())
            throw new IllegalStateException("无法定位已安装的 APK dex 路径");
        String command="CLASSPATH="+quote(apk)+" /system/bin/app_process /system/bin "
               +"dev.yz.dnsobserver.DnsIpv6RootProbe "+token+" "+proto+" "+stage;
        java.lang.Process p=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        Thread read=new Thread(()->{
            try(BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream(),StandardCharsets.UTF_8))){
                String line;while((line=br.readLine())!=null)logs.offer(line.length()>700?line.substring(0,700):line);
            }catch(Exception ignored){}
        },"DNS-IP6-ListenerLog");
        read.setDaemon(true);read.start();
        return p;
    }
    private static String waitFor(BlockingQueue<String> logs,String expected,long timeout,StringBuilder report) throws InterruptedException {
        long expiry=android.os.SystemClock.elapsedRealtime()+timeout;
        while(true){
            long left=expiry-android.os.SystemClock.elapsedRealtime();
            if(left<=0)return "TIMEOUT";
            String line=logs.poll(left,TimeUnit.MILLISECONDS);
            if(line==null)return "TIMEOUT";
            report.append("Root监听：").append(line).append('\n');
            if(line.contains("DNS6PROBE ERROR")||line.contains("RECV_MISMATCH"))return "ERROR";
            if(line.contains("DNS6PROBE "+expected))return "OK";
        }
    }
    private static void send(String proto,String stage,String token,InetAddress address,int port) throws Exception {
        boolean dns53="DNS53".equals(stage);
        byte[] payload=dns53?DnsPacket.probeQuestion():
                ("DNS6-"+proto+"-"+stage+"-"+token).getBytes(StandardCharsets.US_ASCII);
        if("UDP".equals(proto)){
            try(DatagramSocket socket=new DatagramSocket(null)){
                socket.bind(new InetSocketAddress(InetAddress.getByName("::"),0));
                socket.send(new DatagramPacket(payload,payload.length,address,port));
            }
        } else {
            try(Socket tcp=new Socket()){
                tcp.connect(new InetSocketAddress(address,port),3500);
                if(dns53){tcp.getOutputStream().write((payload.length>>>8)&255);tcp.getOutputStream().write(payload.length&255);}
                tcp.getOutputStream().write(payload);
                tcp.getOutputStream().flush();
            }
        }
    }
    private static boolean single(Context ctx,String token,String proto,String stage,StringBuilder report) {
        java.lang.Process proc=null;
        BlockingQueue<String> queue=new LinkedBlockingQueue<>();
        String name=proto+" "+("DIRECT".equals(stage)?"基础回环":("LOOP".equals(stage)?"TPROXY 回环":("DNS53".equals(stage)?"App 专属 DNS53 请求捕获":"本机非回环"));
        try {
            proc=listener(ctx,token,proto,stage,queue);
            String ready=waitFor(queue,"READY",6000,report);
            if(!"OK".equals(ready)){report.append(name).append("：透明 Socket 未就绪（").append(ready).append("）\n");return false;}
            InetAddress target=InetAddress.getByName(("LOCAL".equals(stage)||"DNS53".equals(stage))?DOC_IP:"::1");
            int sendPort="DIRECT".equals(stage)?("TCP".equals(proto)?DIRECT_TCP_PORT:LISTEN_PORT):("DNS53".equals(stage)?53:TEST_PORT);
            send(proto,stage,token,target,sendPort);
            String observed=waitFor(queue,"RECV_OK",5000,report);
            boolean success="OK".equals(observed);
            report.append(name).append("：").append(success?"成功":"未通过（"+observed+"）").append('\n');
            return success;
        }catch(Exception e){report.append(name).append("：异常 ").append(e.getClass().getSimpleName())
                   .append(' ').append(e.getMessage()).append('\n');return false;}
        finally{
            if(proc!=null){
                proc.destroy();
                // RECV_OK / ERROR is printed only after Root sockets close.
                // Allow the su/app_process wrapper to exit normally before signalling it.
                try{
                    if(!proc.waitFor(1200,TimeUnit.MILLISECONDS)){
                        proc.destroy();
                        if(!proc.waitFor(350,TimeUnit.MILLISECONDS))proc.destroyForcibly();
                    }
                }catch(InterruptedException e){Thread.currentThread().interrupt();proc.destroyForcibly();}
            }
        }
    }
    private static void stageStatus(Context ctx,String token,StringBuilder report){
        try{report.append("隔离规则计数与路由：\n").append(root(ctx,"status",token,6)).append('\n');}
        catch(Exception e){report.append("读取状态失败：").append(e.getMessage()).append('\n');}
    }
    private static boolean cleanup(Context ctx,StringBuilder report){
        try{
            String result=recover(ctx);
            report.append("恢复及残留检查：").append(result).append('\n');
            return result.contains("VERIFY_CLEAN");
        }catch(Exception e){
            report.append("恢复/核对失败：").append(e.getMessage()).append("；请点击一键恢复并核查。\n");
            return false;
        }
    }
    public static String run(Context ctx){
        String token=UUID.randomUUID().toString().replace("-","");
        StringBuilder report=new StringBuilder("IPv6 TPROXY 分阶段现场实验 v0.5.7\n先测合成流量，再仅匹配本 App UID 发往文档地址的 DNS53 请求；不拦截其他 App，不返回 DNS 应答。\n");
        boolean clean=true;
        try {
            boolean udp=single(ctx,token,"UDP","DIRECT",report);
            boolean tcp=single(ctx,token,"TCP","DIRECT",report);
            if(!udp || !tcp) {
                report.append("基础回环尚不完整，跳过后续实验。\n");
            } else {
                boolean loopUdp=false,loopTcp=false;
                try {
                    report.append(root(ctx,"install-loop",token,10)).append('\n');
                    loopUdp=single(ctx,token,"UDP","LOOP",report);
                    loopTcp=single(ctx,token,"TCP","LOOP",report);
                    stageStatus(ctx,token,report);
                } finally {clean=cleanup(ctx,report);}
                if(!clean || !loopUdp || !loopTcp) {
                    report.append("回环阶段或残留核对未通过；跳过本机非回环策略路由实验。\n");
                } else {
                    boolean localUdp=false,localTcp=false;
                    try {
                        report.append(root(ctx,"install-local",token,10)).append('\n');
                        localUdp=single(ctx,token,"UDP","LOCAL",report);
                        localTcp=single(ctx,token,"TCP","LOCAL",report);
                        stageStatus(ctx,token,report);
                    } finally {clean=cleanup(ctx,report);}
                    if(!clean)report.append("注意：本机路由阶段存在清理异常，请点击一键恢复并核查！\n");
                    if(clean && localUdp && localTcp) {
                        try {
                            report.append(root(ctx,"install-dns",token,10)).append('\n');
                            boolean dnsUdp=single(ctx,token,"UDP","DNS53",report);
                            boolean dnsTcp=single(ctx,token,"TCP","DNS53",report);
                            stageStatus(ctx,token,report);
                            report.append("DNS53 报文捕获：").append(dnsUdp&&dnsTcp?"UDP/TCP 全部通过":"存在失败").append('\n');
                        } finally {clean=cleanup(ctx,report);}
                    } else report.append("前置本机流量或清理检查失败，跳过 DNS53 阶段。\n");
                }
            }
        }catch(Throwable e){report.append("实验异常：").append(e.getClass().getSimpleName())
                .append(' ').append(e.getMessage()).append('\n');}
        finally{cleanup(ctx,report);}
        return report.append("结论边界：DNS53 只检验本 App 发往文档地址的真实 DNS 查询能否到达透明 Socket；尚未验证响应返回、上游转发或全机接管。")
                .toString();
    }
}
