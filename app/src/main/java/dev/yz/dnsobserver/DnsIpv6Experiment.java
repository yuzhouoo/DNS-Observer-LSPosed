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
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Reversible ::1-only TPROXY experiment; root listener avoids app UID capability limitations.
 * This deliberately DOES NOT set Android fwmark policy routes or intercept real DNS 53. */
public final class DnsIpv6Experiment {
    private static final String SCRIPT_NAME="dns-ipv6-probe-v053.sh";
    private static final int CLIENT_PORT=15453, LISTEN_PORT=15454;
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
            throw new IllegalStateException("无法保护 IPv6 Root 脚本文件权限");
        return f;
    }
    private static String root(Context ctx,String mode,String token,int seconds) throws Exception {
        if(!mode.matches("install|recover|status")||!token.matches("[A-Za-z0-9_-]{1,64}"))
            throw new IllegalArgumentException("Invalid probe arguments");
        String path=script(ctx).getAbsolutePath();
        if(!path.matches("/[a-zA-Z0-9_./-]+"))throw new IllegalArgumentException("unsafe path");
        String command="/system/bin/sh "+path+" "+mode+" "+Process.myUid()+" "+token;
        java.lang.Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        ByteArrayOutputStream output=new ByteArrayOutputStream();
        Thread reader=new Thread(()->{
            try(InputStream in=process.getInputStream()) {
                byte[] b=new byte[1024];int n;
                while((n=in.read(b))!=-1) {
                    synchronized(output){int capacity=8192-output.size();if(capacity>0)output.write(b,0,Math.min(n,capacity));}
                }
            } catch(Exception ignored){}
        },"DNS-IP6-RootLog");
        reader.setDaemon(true);reader.start();
        if(!process.waitFor(seconds,TimeUnit.SECONDS)) {
            process.destroyForcibly();throw new IllegalStateException("Root "+mode+" 超时");
        }
        String result=output.toString(StandardCharsets.UTF_8.name()).trim();
        if(process.exitValue()!=0)throw new IllegalStateException("Root "+mode+" 返回码 "+process.exitValue()+": "+result);
        return result;
    }
    public static String recover(Context ctx) throws Exception {
        return root(ctx,"recover","cleanup",10);
    }
    private static String quote(String text) {
        return "'"+text.replace("'","'\\''")+"'";
    }
    private static java.lang.Process startRootListener(Context ctx,String token,BlockingQueue<String> events) throws Exception {
        String apk=ctx.getApplicationInfo().sourceDir;
        if(apk==null||!apk.startsWith("/data/app/")||!new File(apk).isFile())
            throw new IllegalStateException("无法定位当前 APK 的只读 dex 路径");
        // app_process loads this APK's classes.dex as the Root process classpath.
        // No setcap, copying executables, kernel modification, or route changes.
        String command="CLASSPATH="+quote(apk)+" /system/bin/app_process /system/bin "
                +"dev.yz.dnsobserver.DnsIpv6RootProbe "+token;
        java.lang.Process p=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        Thread reader=new Thread(()->{
            try(BufferedReader in=new BufferedReader(new InputStreamReader(p.getInputStream(),StandardCharsets.UTF_8))) {
                String line;
                while((line=in.readLine())!=null) {
                    if(line.length()>500)line=line.substring(0,500);
                    events.offer(line);
                }
            }catch(Exception ignored){}
        },"DNS-IP6-RootProbe-Output");
        reader.setDaemon(true);reader.start();
        return p;
    }
    private static String await(BlockingQueue<String> q,String expected,long millis,StringBuilder report)
            throws InterruptedException {
        long deadline=android.os.SystemClock.elapsedRealtime()+millis;
        while(true) {
            long remain=deadline-android.os.SystemClock.elapsedRealtime();
            if(remain<=0)return "TIMEOUT";
            String line=q.poll(remain,TimeUnit.MILLISECONDS);
            if(line==null)return "TIMEOUT";
            report.append("Root监听：").append(line).append('\n');
            if(line.contains("DNS6PROBE ERROR")||line.contains("_ERROR")||line.contains("_MISMATCH"))return "ERROR";
            if(line.contains("DNS6PROBE "+expected))return "OK";
        }
    }
    private static void send(DatagramSocket sender,InetAddress target,String token,int port) throws Exception {
        byte[] packet=("DNS6-"+(port==LISTEN_PORT?"DIRECT-":"TPROXY-")+token).getBytes(StandardCharsets.US_ASCII);
        sender.send(new DatagramPacket(packet,packet.length,target,port));
    }
    public static String run(Context ctx) {
        String token=UUID.randomUUID().toString().replace("-","");
        StringBuilder report=new StringBuilder("IPv6 TPROXY 隔离实验 v0.5.3（仅 ::1:15453）\n");
        java.lang.Process listener=null;
        BlockingQueue<String> logs=new LinkedBlockingQueue<>();
        try(DatagramSocket sender=new DatagramSocket(null)) {
            InetAddress loopback=InetAddress.getByName("::1");
            sender.bind(new InetSocketAddress(loopback,0));
            listener=startRootListener(ctx,token,logs);
            String ready=await(logs,"READY",7000,report);
            if(!"OK".equals(ready)) {
                report.append("透明 Socket 未就绪：").append(ready)
                      .append("。如提示 EPERM，检查 Root 进程能力与 SELinux。\n");
            } else {
                send(sender,loopback,token,LISTEN_PORT);
                String direct=await(logs,"DIRECT_OK",3500,report);
                report.append("普通 IPv6 回环直连收包：").append("OK".equals(direct)?"成功":"失败（"+direct+"）").append('\n');
                if(!"OK".equals(direct)) {
                    report.append("基础回环未通过，跳过 TPROXY 规则安装。\n");
                } else {
                    root(ctx,"install",token,10);
                    report.append("隔离 TPROXY 规则：已安装；20 秒自动恢复保护已启动。\n");
                    send(sender,loopback,token,CLIENT_PORT);
                    String redirect=await(logs,"TPROXY_OK",4800,report);
                    report.append("TPROXY UDP 投递结果：")
                          .append("OK".equals(redirect)?"成功":"未验证成功（"+redirect+"）").append('\n');
                    try{report.append("规则计数：\n").append(root(ctx,"status",token,5)).append('\n');}
                    catch(Exception e){report.append("计数读取失败：").append(e.getMessage()).append('\n');}
                }
            }
        }catch(Exception e) {
            report.append("实验异常：").append(e.getClass().getSimpleName()).append(" ").append(e.getMessage()).append('\n');
        }finally {
            if(listener!=null) {
                listener.destroy();
                try{if(!listener.waitFor(500,TimeUnit.MILLISECONDS))listener.destroyForcibly();}
                catch(InterruptedException e){Thread.currentThread().interrupt();listener.destroyForcibly();}
            }
            try{report.append("恢复：").append(recover(ctx)).append('\n');}
            catch(Exception e){report.append("恢复失败；20 秒 Root 守护仍会尝试恢复：").append(e.getMessage()).append('\n');}
        }
        return completed(report);
    }
    private static String completed(StringBuilder b) {
        return b.append("结论范围：这只验证 ::1 回环 TPROXY，不能代表全机 IPv6 DNS 接管已实现。")
                .toString();
    }
}
