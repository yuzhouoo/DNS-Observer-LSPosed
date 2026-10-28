package dev.yz.dnsobserver;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Process;
import android.os.SystemClock;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Explicit opt-in IPv6 global-unicast UDP/TCP DNS53 forwarding.
 * Starts as an APP-UID-only multi-destination selftest, expands scope only
 * after four successful client response checks. Root UID is always excluded. */
public final class DnsIpv6GlobalController {
    private static final Object LOCK=new Object();
    private static final String SCRIPT="dns-ipv6-global-v061.sh";
    private static final String PREF_LOG="ipv6_global_log";
    private static final String[] DOCS={"2001:db8:ffff::53","2001:db8:ffff::54"};
    private static java.lang.Process process;
    private static boolean starting,ownsRules,promoted;
    private static String token;
    private static final LinkedBlockingQueue<String> signals=new LinkedBlockingQueue<>();
    private DnsIpv6GlobalController(){}
    private static final class Endpoint {
        final InetAddress ip;final int port;
        Endpoint(InetAddress ip,int port){this.ip=ip;this.port=port;}
    }
    private static void log(Context ctx,String line){
        synchronized(DnsIpv6GlobalController.class){
            SharedPreferences prefs=ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE);
            String value=prefs.getString(PREF_LOG,"")+line+"\n";
            if(value.length()>9500)value="[更早的记录已截断]\n"+value.substring(value.length()-8600);
            prefs.edit().putString(PREF_LOG,value).apply();
        }
    }
    public static String report(Context ctx){
        return ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE)
                .getString(PREF_LOG,"");
    }
    public static void clearLog(Context ctx){
        synchronized(DnsIpv6GlobalController.class){
            ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE)
                    .edit().remove(PREF_LOG).commit();
        }
    }
    public static boolean isRunning(){
        synchronized(LOCK){return starting||(process!=null && process.isAlive());}
    }
    private static File script(Context ctx)throws Exception{
        File file=new File(ctx.getFilesDir(),SCRIPT);
        if(file.isFile() && file.length()>3500)return file;
        try(InputStream in=ctx.getAssets().open("dns-ipv6-global.sh");FileOutputStream out=new FileOutputStream(file)){
            byte[] buffer=new byte[4096];int n;
            while((n=in.read(buffer))!=-1)out.write(buffer,0,n);
            out.getFD().sync();
        }
        if(!file.setReadable(true,true)||!file.setWritable(true,true))throw new IllegalStateException("Root 脚本权限错误");
        return file;
    }
    private static String root(Context ctx,String mode,String session,int seconds)throws Exception{
        if(!mode.matches("install-probe|promote|recover|status")||!session.matches("[a-zA-Z0-9_-]{1,64}"))
            throw new IllegalArgumentException("Invalid global IPv6 command");
        String path=script(ctx).getAbsolutePath();
        if(!path.matches("/[a-zA-Z0-9_./-]+"))throw new IllegalStateException("Unexpected script path");
        String command="/system/bin/sh "+path+" "+mode+" "+Process.myUid()+" "+session;
        java.lang.Process p=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        Thread output=new Thread(()->{
            try(InputStream in=p.getInputStream()){
                byte[] data=new byte[1024];int n;
                while((n=in.read(data))!=-1){synchronized(buffer){if(buffer.size()<12000)buffer.write(data,0,Math.min(n,12000-buffer.size()));}}
            }catch(Exception ignored){}
        },"IPv6-global-root-capture");
        output.setDaemon(true);output.start();
        if(!p.waitFor(seconds,TimeUnit.SECONDS)){p.destroyForcibly();throw new IllegalStateException("Root "+mode+" 超时");}
        String result=buffer.toString(StandardCharsets.UTF_8.name()).trim();
        if(p.exitValue()!=0)throw new IllegalStateException("Root "+mode+" rc="+p.exitValue()+" "+result);
        return result;
    }
    private static List<Endpoint> preflight(Context ctx)throws Exception{
        SharedPreferences prefs=ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE);
        String[] hosts={prefs.getString("host",""),prefs.getString("sub_host",""),prefs.getString("secondary_host","")};
        String[] ports={"port","sub_port","secondary_port"};
        String[] names={"主","从","备"};
        List<Endpoint> result=new ArrayList<>();
        for(int i=0;i<3;i++){
            String host=hosts[i]==null?"":hosts[i].trim();if(host.isEmpty())continue;
            int port=Integer.parseInt(prefs.getString(ports[i],"31017").trim());
            if(port<1||port>65535)throw new IllegalArgumentException(names[i]+"端口不合法");
            InetAddress[] addresses=DnsBootstrap.resolve(host,prefs.getString("bootstrap",""));
            boolean ready=false;
            for(int n=0;n<Math.min(addresses.length,6);n++){
                InetAddress ip=addresses[n];if(!DnsUpstreamExchange.permittedUpstream(ip))continue;
                DnsProbe.Sample udp=DnsProbe.measure(ip,port,"UDP"),tcp=DnsProbe.measure(ip,port,"TCP");
                if(udp.success&&tcp.success){
                    result.add(new Endpoint(ip,port));
                    log(ctx,"上游预检 "+names[i]+" "+ip.getHostAddress()+":"+port+" UDP/TCP 通过");
                    ready=true;break;
                }
            }
            if(!ready)log(ctx,"上游预检 "+names[i]+" 未发现可用 UDP/TCP DNS，已跳过");
        }
        if(result.isEmpty())throw new IllegalStateException("没有可用的主/从/备 DNS 上游");
        return result;
    }
    private static String quote(String s){return "'"+s.replace("'","'\\''")+"'";}
    private static java.lang.Process spawn(Context ctx,String session,List<Endpoint> servers)throws Exception{
        String apk=ctx.getApplicationInfo().sourceDir;
        if(apk==null||!apk.startsWith("/data/app/")||!new File(apk).isFile())
            throw new IllegalStateException("未找到已安装 APK");
        StringBuilder command=new StringBuilder("CLASSPATH=").append(quote(apk))
            .append(" /system/bin/app_process /system/bin dev.yz.dnsobserver.DnsIpv6GlobalDaemon ").append(session);
        for(Endpoint server:servers){
            String ip=server.ip.getHostAddress();
            if(!ip.matches("[0-9a-fA-F:.]+"))throw new IllegalArgumentException("无效数值 DNS IP");
            command.append(' ').append(ip).append(' ').append(server.port);
        }
        java.lang.Process p=new ProcessBuilder("su","-c",command.toString()).redirectErrorStream(true).start();
        Thread output=new Thread(()->{
            try(BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream(),StandardCharsets.UTF_8))){
                String line;while((line=br.readLine())!=null){
                    // Only meaningful events; no per-success log flood.
                    if(line.startsWith("DNS6GLOBAL READY")||line.startsWith("DNS6GLOBAL ERROR")||
                            line.startsWith("DNS6GLOBAL STOP")||line.contains("ERROR")||
                            line.startsWith("DNS6GLOBAL FAILOVER_OK")||line.startsWith("DNS6GLOBAL UNHEALTHY")){
                        log(ctx,line.length()>350?line.substring(0,350):line);
                    }
                    if(line.startsWith("DNS6GLOBAL READY")||line.startsWith("DNS6GLOBAL ERROR"))signals.offer(line);
                }
            }catch(Exception ex){
                // Process shutdown can terminate the pipe normally; no scary false error.
                if(p.isAlive())log(ctx,"Root 日志流意外断开："+ex.getClass().getSimpleName());
            }
        },"IPv6-global-output");output.setDaemon(true);output.start();return p;
    }
    private static boolean probe(String protocol,String target)throws Exception{
        InetAddress address=InetAddress.getByName(target);
        byte[] request=DnsPacket.probeQuestion();byte[] response;
        if("UDP".equals(protocol)){
            try(DatagramSocket socket=new DatagramSocket(null)){
                socket.bind(new InetSocketAddress(InetAddress.getByName("::"),0));
                socket.setSoTimeout(3600);
                socket.send(new DatagramPacket(request,request.length,address,53));
                byte[] buf=new byte[4096];DatagramPacket result=new DatagramPacket(buf,buf.length);
                socket.receive(result);
                if(!address.equals(result.getAddress())||result.getPort()!=53)return false;
                response=Arrays.copyOf(buf,result.getLength());
            }
        }else{
            try(Socket socket=new Socket()){
                socket.connect(new InetSocketAddress(address,53),3200);
                socket.setSoTimeout(3600);
                DataOutputStream out=new DataOutputStream(socket.getOutputStream());
                out.writeShort(request.length);out.write(request);out.flush();
                DataInputStream in=new DataInputStream(socket.getInputStream());
                int size=in.readUnsignedShort();if(size<12||size>4096)return false;
                response=new byte[size];in.readFully(response);
            }
        }
        int rcode=response.length>3?response[3]&15:-1;
        return DnsPacket.validReply(request,response)&&(rcode==0||rcode==3)&&!DnsPacket.truncated(response);
    }
    private static boolean selfTest(Context app){
        boolean all=true;
        for(String dest:DOCS){
            for(String protocol:new String[]{"UDP","TCP"}){
                boolean ok=false;
                try{ok=probe(protocol,dest);}catch(Exception ex){log(app,"原目标回包测试异常："+ex.getClass().getSimpleName()+" "+ex.getMessage());}
                log(app,"自检 "+protocol+" "+dest+"："+(ok?"通过":"失败"));
                all&=ok;
            }
        }
        return all;
    }
    /** Manual action; no boot start. Rule broadening is only reached after four real replies. */
    public static String start(Context ctx){
        Context app=ctx.getApplicationContext();
        synchronized(LOCK){
            if(starting||(process!=null&&process.isAlive()))return "IPv6 全局试用已经运行或启动中";
            if(DnsIpv6PilotController.isRunning())return "请先停止原 IPv6 受限试运行，不能并行开启";
            starting=true;ownsRules=false;promoted=false;signals.clear();
            token=UUID.randomUUID().toString().replace("-","");
            java.lang.Process started=null;
            boolean installAttempted=false;
            log(app,"启动独立 IPv6 DNS 全局试用（非 Root UID，145 秒，独立 180 秒恢复）");
            try{
                List<Endpoint> servers=preflight(app);
                started=spawn(app,token,servers);process=started;
                String ready=signals.poll(8000,TimeUnit.MILLISECONDS);
                if(ready==null||!ready.startsWith("DNS6GLOBAL READY"))throw new IllegalStateException("代理未就绪："+ready);
                installAttempted=true;
                String installed=root(app,"install-probe",token,12);ownsRules=true;log(app,installed);
                if(!selfTest(app))throw new IllegalStateException("原始 IPv6 目标/回包自检未全通过，禁止扩大匹配");
                log(app,root(app,"promote",token,12));promoted=true;
                // One more check with broad selectors active; failures always revert.
                if(!probe("UDP",DOCS[0])||!probe("TCP",DOCS[1]))
                    throw new IllegalStateException("扩大规则后的回包验证失败，立即恢复");
                final java.lang.Process monitor=started;
                Thread guard=new Thread(()->{
                    try{monitor.waitFor();}catch(InterruptedException ex){Thread.currentThread().interrupt();}
                    synchronized(LOCK){
                        if(process!=monitor)return;
                        log(app,"Root 服务退出：尝试自动撤销全局 IPv6 规则");
                        try{String result=root(app,"recover",token,12);ownsRules=false;promoted=false;log(app,result);}
                        catch(Exception ex){log(app,"自动清理未确认："+ex.getMessage());}
                        process=null;
                    }
                },"IPv6-global-exit-guard");guard.setDaemon(true);guard.start();
                log(app,"全局 IPv6 DNS53 已开启（UID 0 除外），最多 145 秒；不影响 IPv4");
                return "IPv6 DNS53 已启用：多地址 UDP/TCP 自检全部通过；到期自动恢复";
            }catch(Exception error){
                log(app,"启用失败："+error.getClass().getSimpleName()+" "+error.getMessage());
                if(started!=null){started.destroy();try{if(!started.waitFor(700,TimeUnit.MILLISECONDS))started.destroyForcibly();}catch(Exception ignored){started.destroyForcibly();}}
                process=null;
                // A PRECHECK_FAILED never owns a chain; do not touch another session.
                // Other failures can be partial installations, so always verify recovery.
                if(ownsRules||(installAttempted && (error.getMessage()==null ||
                        !error.getMessage().contains("PRECHECK_FAILED")))){
                    try{log(app,root(app,"recover",token,12));ownsRules=false;promoted=false;}
                    catch(Exception ex){log(app,"清理未确认："+ex.getMessage());}
                }
                return "未开启 IPv6 全局 DNS，已执行回滚："+error.getMessage();
            }finally{starting=false;}
        }
    }
    public static String stop(Context ctx){
        synchronized(LOCK){
            if(process!=null){
                process.destroy();
                try{if(!process.waitFor(800,TimeUnit.MILLISECONDS))process.destroyForcibly();}
                catch(Exception ex){process.destroyForcibly();}
                process=null;
            }
            String result;
            try{result=root(ctx,"recover","cleanup",14);ownsRules=false;promoted=false;}
            catch(Exception ex){result="RECOVERY_FAILED: "+ex.getMessage();}
            log(ctx,"关闭 IPv6 全局 DNS："+result);
            return result;
        }
    }
    public static String status(Context ctx){
        try{return root(ctx,"status","status",7);}catch(Exception ex){return "状态查询失败："+ex.getMessage();}
    }
}
