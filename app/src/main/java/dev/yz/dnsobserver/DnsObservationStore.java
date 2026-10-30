package dev.yz.dnsobserver;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import java.util.ArrayDeque;
import java.util.ArrayList;

/** Bounded app-local asynchronous writer. Never block a DNS forwarding worker on SQLite. */
public final class DnsObservationStore {
    private static final ArrayDeque<Bundle> queue=new ArrayDeque<>();
    private static Handler handler;
    private static DnsDb database;
    private static long dropped;
    private static boolean scheduled;
    public static boolean enabled(Context c){return c.getSharedPreferences(SecureProvider.PREFS,0).getBoolean("enabled",true)&&c.getSharedPreferences(SecureProvider.PREFS,0).getBoolean("detailed_observation",false);}
    public static void offer(Context c,Bundle item){
        if(!enabled(c))return;Context app=c.getApplicationContext();
        synchronized(queue){
            if(queue.size()>=400){queue.removeFirst();dropped++;}
            queue.addLast(item);
            if(handler==null){HandlerThread t=new HandlerThread("DNS-detailed-writer");t.start();handler=new Handler(t.getLooper());}
            if(!scheduled){scheduled=true;handler.postDelayed(()->flush(app),700);}
        }
    }
    private static void flush(Context c){
        ArrayList<Bundle> batch=new ArrayList<>();long lost;
        synchronized(queue){for(int k=0;k<40&&!queue.isEmpty();k++)batch.add(queue.removeFirst());lost=dropped;}
        try{if(enabled(c)&&!batch.isEmpty()){DnsMetadata.enrichBatch(c,batch);if(database==null)database=new DnsDb(c);database.insertBatch(c,batch);}}
        catch(Exception error){synchronized(queue){dropped+=batch.size();lost=dropped;}}
        if(lost>0)c.getSharedPreferences(SecureProvider.PREFS,0).edit().putLong("detail_dropped",lost).apply();
        synchronized(queue){if(!queue.isEmpty())handler.postDelayed(()->flush(c),100);else scheduled=false;}
    }
    public static void proxy(Context c,byte[] query,byte[] answer,String incoming,String upstream,long elapsed,String error){
        if(!enabled(c))return;String name=DnsObservation.questionName(query);if(name.isEmpty())return;
        Bundle b=new Bundle();b.putLong("ts",System.currentTimeMillis());b.putString("host",name);b.putInt("uid",-1);
        b.putString("packages","来源 UID 未获取（接管流量）");b.putString("appName","DNS 接管流量 · UID 未获取");
        b.putString("transport",incoming);b.putString("recordKind","PROXY");b.putString("evidence","PROXY_DNS_RESPONSE");
        b.putString("dnsType",incoming+"（代理实际收到的协议）");b.putString("dnsServer",upstream);
        b.putString("dnsSource","代理收到查询及上游结果；不代表客户端已收到回包");
        b.putString("detail","QTYPE="+DnsObservation.typeName(DnsObservation.questionType(query))+"；"+error);
        String[] addresses=DnsObservation.answerAddresses(answer);b.putStringArray("ips",addresses);b.putInt("total",addresses.length);
        b.putInt("latency",(int)Math.max(0,Math.min(60000,elapsed)));b.putInt("rc",answer!=null&&answer.length>3?answer[3]&15:2);
        offer(c,b);
    }
    public static void rootLine(Context c,String line){
        if(!enabled(c)||line.length()>12000)return;
        try{String[] p=line.split("\\|",7);if(p.length!=7)return;
            byte[] query=java.util.Base64.getDecoder().decode(p[2]);byte[] answer=java.util.Base64.getDecoder().decode(p[6]);
            if(!("UDP".equals(p[1])||"TCP".equals(p[1]))||!DnsPacket.validReply(query,answer))return;
            proxy(c,query,answer,p[1],p[4],Long.parseLong(p[5]),"上游结果；来源 UID 未获取");
        }catch(Exception ignored){}
    }
}
