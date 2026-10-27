package dev.yz.dnsobserver;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Bundle;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Network configuration snapshot only: it is NOT per-query DNS packet provenance.
 * Runs inside the app provider process with ACCESS_NETWORK_STATE granted.
 */
public final class DnsMetadata {
    private DnsMetadata() { }

    private static final class Snapshot {
        final String type, server, source;
        Snapshot(String type,String server,String source) {
            this.type=type;this.server=server;this.source=source;
        }
    }

    private static Snapshot snapshot(Context ctx, int netId) {
        try {
            ConnectivityManager cm=(ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if(cm==null) return new Snapshot("系统解析事件（协议不可判定）","未获取到系统网络服务","未获取网络配置");
            Network selected=null;
            String scope="";
            if(netId>0) {
                for(Network candidate:cm.getAllNetworks()) {
                    long handle=candidate.getNetworkHandle();
                    if((int)(handle >>> 32)==netId) {
                        selected=candidate;scope="事件 NetID "+netId;break;
                    }
                }
            }
            if(selected==null) {
                selected=cm.getActiveNetwork();
                scope="当前默认网络（不一定等于事件 NetID "+netId+"）";
            }
            LinkProperties properties=selected==null?null:cm.getLinkProperties(selected);
            if(properties==null) return new Snapshot("系统解析事件（协议不可判定）",
                    "没有可用的系统 DNS 配置",scope+"；读取失败或网络已切换");
            StringBuilder server=new StringBuilder();
            for(InetAddress ip:properties.getDnsServers()) {
                if(server.length()>0)server.append(", ");
                server.append(ip.getHostAddress());
            }
            boolean dot=properties.isPrivateDnsActive();
            String privateHost=properties.getPrivateDnsServerName();
            if(dot && privateHost!=null && !privateHost.isEmpty()) {
                if(server.length()>0)server.append(" | ");
                server.append("Private DNS: ").append(privateHost);
            }
            return new Snapshot(dot?"私人 DNS 配置已启用（DoT；非逐请求证据）":
                    "系统解析事件（传输协议无法由 Hook 判定）",
                    server.length()>0?server.toString():"网络未公开 DNS 地址",
                    scope+" 的系统 DNS 配置快照，非实际请求目标");
        } catch (Throwable t) {
            return new Snapshot("系统解析事件（协议不可判定）",
                    "系统 DNS 配置不可读取",
                    "配置读取异常："+t.getClass().getSimpleName());
        }
    }

    private static boolean unresolved(String text) {
        return text==null||text.trim().isEmpty()||"未知".equals(text)||
               "未知应用".equals(text)||"未配置".equals(text);
    }

    static void enrichBatch(Context ctx, ArrayList<Bundle> events) {
        HashMap<Integer,Snapshot> networks=new HashMap<>();
        HashMap<String,String> appLabels=new HashMap<>();
        PackageManager pm=ctx.getPackageManager();
        for(Bundle event:events) {
            if(event==null)continue;
            int netId=event.getInt("net",0);
            Snapshot s=networks.get(netId);
            if(s==null){s=snapshot(ctx,netId);networks.put(netId,s);}
            if(unresolved(event.getString("dnsType")))event.putString("dnsType",s.type);
            if(unresolved(event.getString("dnsServer"))) {
                event.putString("dnsServer",s.server);
                event.putString("dnsSource",s.source);
            }
            String[] packages=parsePackages(event.getString("packages",""));
            int uid=event.getInt("uid",-1);
            if(packages.length==0 && uid>=0) {
                try {packages=pm.getPackagesForUid(uid);}
                catch(Throwable ignored) { }
                if(packages!=null && packages.length>0) {
                    event.putString("packages",android.text.TextUtils.join(", ",packages));
                }
            }
            if(packages==null)packages=new String[0];
            if(unresolved(event.getString("appName"))) {
                String label="";
                for(String pkg:packages) {
                    String cached=appLabels.get(pkg);
                    if(cached==null) {
                        cached="";
                        try {
                            ApplicationInfo ai=pm.getApplicationInfo(pkg,0);
                            CharSequence name=pm.getApplicationLabel(ai);
                            if(name!=null)cached=name.toString().trim();
                        } catch(Throwable ignored) { }
                        appLabels.put(pkg,cached);
                    }
                    if(!cached.isEmpty()) {label=cached;break;}
                }
                if(label.isEmpty() && packages.length>0)label=packages[0];
                if(label.isEmpty())label="UID "+uid+"（未关联应用）";
                event.putString("appName",TextPolicy.clamp(label,160));
            }
        }
    }

    private static String[] parsePackages(String source) {
        if(source==null||source.trim().isEmpty()||source.startsWith("UID "))return new String[0];
        String[] raw=source.split(",");
        ArrayList<String> cleaned=new ArrayList<>();
        for(String p:raw) {
            String value=p.trim();
            if(!value.isEmpty())cleaned.add(value);
        }
        return cleaned.toArray(new String[0]);
    }
}
