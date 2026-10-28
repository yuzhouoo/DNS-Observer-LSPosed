package dev.yz.dnsobserver;

import android.content.Context;
import android.os.Process;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.FileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Isolated, reversible LOOPBACK IPv6 TPROXY experiment.
 * Does not claim to intercept real on-device IPv6 DNS traffic.
 * No policy-routing modifications; no 53-port or Android fwmark changes.
 */
public final class DnsIpv6Experiment {
    private static final String SCRIPT_NAME="dns-ipv6-probe-v052.sh";
    private static final int CLIENT_PORT=15453;
    private static final int LISTEN_PORT=15454;
    private DnsIpv6Experiment() { }

    private static File script(Context ctx) throws Exception {
        File f=new File(ctx.getFilesDir(),SCRIPT_NAME);
        if(f.isFile()&&f.length()>400) return f;
        try(InputStream in=ctx.getAssets().open("dns-ipv6-tproxy-probe.sh");
            FileOutputStream out=new FileOutputStream(f,false)) {
            byte[] buf=new byte[4096];int n;
            while((n=in.read(buf))!=-1)out.write(buf,0,n);
            out.getFD().sync();
        }
        f.setReadable(true,true);f.setWritable(true,true);
        return f;
    }
    private static String root(Context ctx,String mode,String token,int seconds) throws Exception {
        if(!mode.matches("install|recover|status|watch")||!token.matches("[A-Za-z0-9_-]{1,64}"))
            throw new IllegalArgumentException("Invalid probe arguments");
        String path=script(ctx).getAbsolutePath();
        if(!path.matches("/[a-zA-Z0-9_./-]+"))throw new IllegalArgumentException("unsafe path");
        String command="/system/bin/sh "+path+" "+mode+" "+Process.myUid()+" "+token;
        if("watch".equals(mode))command+=" </dev/null >/dev/null 2>&1 &";
        java.lang.Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        ByteArrayOutputStream output=new ByteArrayOutputStream();
        Thread reader=new Thread(()->{
            try(InputStream in=process.getInputStream()) {
                byte[] buffer=new byte[1024];int n;
                while((n=in.read(buffer))!=-1) {
                    synchronized(output){ if(output.size()<8192)output.write(buffer,0,Math.min(n,8192-output.size())); }
                }
            } catch(Exception ignored) { }
        },"DNS-IP6-RootLog");
        reader.setDaemon(true);reader.start();
        if(!process.waitFor(seconds,TimeUnit.SECONDS)) {
            process.destroyForcibly();throw new IllegalStateException("Root "+mode+" 超时");
        }
        String result=output.toString(StandardCharsets.UTF_8.name()).trim();
        if(process.exitValue()!=0)throw new IllegalStateException("Root "+mode+" 返回码 " +process.exitValue()+": "+result);
        return result;
    }
    public static String recover(Context ctx) throws Exception {
        return root(ctx,"recover","cleanup",10);
    }

    public static String run(Context ctx) {
        String token=UUID.randomUUID().toString().replace("-","");
        StringBuilder report=new StringBuilder();
        InetAddress local;
        try {local=InetAddress.getByName("::1");}
        catch(Exception e){return "IPv6 回环不可用: "+e.getMessage();}
        FileDescriptor transparentFd=null;
        DatagramSocket fallbackListener=null;
        try(DatagramSocket sending=new DatagramSocket(null)) {
            sending.bind(new InetSocketAddress(local,0));
            // Try the real IPV6_TRANSPARENT socket option through Android's public Os API.
            // Linux IPV6_TRANSPARENT socket option is 75. App UID may lack CAP_NET_RAW.
            try {
                transparentFd=Os.socket(OsConstants.AF_INET6,OsConstants.SOCK_DGRAM,OsConstants.IPPROTO_UDP);
                Os.setsockoptInt(transparentFd,OsConstants.IPPROTO_IPV6,75,1);
                Os.setsockoptTimeval(transparentFd,OsConstants.SOL_SOCKET,
                        OsConstants.SO_RCVTIMEO,StructTimeval.fromMillis(1500));
                Os.bind(transparentFd,local,LISTEN_PORT);
                report.append("IPV6_TRANSPARENT Socket：创建成功。\n");
            } catch(Exception denied) {
                if(transparentFd!=null){try{Os.close(transparentFd);}catch(Exception ignored){}transparentFd=null;}
                report.append("IPV6_TRANSPARENT Socket 不可用：")
                      .append(denied.getClass().getSimpleName()).append("（可能缺 CAP_NET_RAW/SELinux）\n");
                fallbackListener=new DatagramSocket(null);
                fallbackListener.bind(new InetSocketAddress(local,LISTEN_PORT));
                fallbackListener.setSoTimeout(1500);
            }
            root(ctx,"install",token,10);
            report.append("IPv6 mangle/TProxy 测试规则：已安装（仅 ::1:15453）。\n");
            // Script already launched a standalone 20s Root watchdog before returning.
            byte[] nonce=("DNSObserverTPROXY-"+token).getBytes(StandardCharsets.US_ASCII);
            sending.send(new DatagramPacket(nonce,nonce.length,local,CLIENT_PORT));
            byte[] data=new byte[128];
            try {
                int count;
                if(transparentFd!=null)count=Os.read(transparentFd,data,0,data.length);
                else {
                    DatagramPacket received=new DatagramPacket(data,data.length);
                    fallbackListener.receive(received);
                    count=received.getLength();
                }
                String body=new String(data,0,count,StandardCharsets.US_ASCII);
                if(body.equals("DNSObserverTPROXY-"+token))
                    report.append("回环 UDP 实测：本地 Socket 收到匹配测试报文。\n");
                else report.append("回环 UDP 实测：收到非预期报文，未通过。\n");
            } catch(Exception timeout) {
                report.append("回环 UDP 实测：未成功接收（")
                      .append(timeout.getClass().getSimpleName())
                      .append("）；需检查 IP6 PREROUTING 是否命中及透明 Socket。\n");
            }
            try {report.append("内核计数器：\n").append(root(ctx,"status",token,5)).append('\n');}
            catch(Exception e){report.append("读取命中计数失败：").append(e.getMessage()).append('\n');}
        } catch(Exception e) {
            report.append("隔离验证未通过：").append(e.getMessage()).append('\n');
        } finally {
            if(transparentFd!=null)try{Os.close(transparentFd);}catch(Exception ignored){}
            if(fallbackListener!=null)fallbackListener.close();
            try {report.append("恢复：").append(recover(ctx)).append('\n');}
            catch(Exception e){report.append("恢复失败！请点击一键恢复；20秒守护程序仍会尝试清理：")
                                  .append(e.getMessage()).append('\n');}
        }
        report.append("注意：这只能验证有限的 IPv6 回环 TPROXY 路径，不能证明本机外网 DNS 已被重定向；未添加任何路由表或拦截 53 端口。");
        return report.toString();
    }
}
