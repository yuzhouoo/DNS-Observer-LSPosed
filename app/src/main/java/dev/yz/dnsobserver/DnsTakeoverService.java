package dev.yz.dnsobserver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** One persistent user-controlled lifecycle for IPv4 NAT and IPv6 TPROXY.
 * No time-based rule removal. Manual OFF overrides boot and auto-repair. */
public final class DnsTakeoverService extends Service {
    public static final String ACTION_START="dev.yz.dnsobserver.TAKEOVER_START";
    public static final String ACTION_STOP="dev.yz.dnsobserver.TAKEOVER_STOP";
    public static final String EVENT_LOG="takeover_events";
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private volatile boolean stopped=true, monitoring;
    private volatile boolean expect4,expect6;
    private boolean fault4,fault6;
    // No retry of a session that never passed IPv6 startup and rule verification.
    private boolean ipv6EverActive,ipv6RepairBlocked;
    private static volatile String uiPhase="idle";
    public static String uiPhase(){return uiPhase;}
    private static final Object EVENTS_LOCK=new Object();

    public static void event(Context ctx,String message) {
        synchronized(EVENTS_LOCK) {
            SharedPreferences prefs=ctx.getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE);
            String when=new SimpleDateFormat("MM-dd HH:mm:ss",Locale.getDefault()).format(new Date());
            String value=prefs.getString(EVENT_LOG,"")+when+"  "+message+"\n";
            if(value.length()>16000)value="[更早记录已截断]\n"+value.substring(value.length()-14500);
            prefs.edit().putString(EVENT_LOG,value).apply();
        }
    }
    public static void clearEvents(Context ctx) {
        synchronized(EVENTS_LOCK) {
            ctx.getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE)
                    .edit().remove(EVENT_LOG).commit();
        }
    }
    public static String events(Context ctx) {
        return ctx.getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE)
                .getString(EVENT_LOG,"");
    }
    public static void requestStart(Context ctx) {
        Intent i=new Intent(ctx,DnsTakeoverService.class).setAction(ACTION_START);
        ctx.startForegroundService(i);
    }
    public static void requestStop(Context ctx) {
        Context app=ctx.getApplicationContext();
        DnsForwardService.cancelPendingStart();
        // Disable recovery BEFORE posting the stop action, even if the service is busy.
        app.getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE).edit()
                .putBoolean("takeover_enabled",false).commit();
        app.startService(new Intent(app,DnsTakeoverService.class).setAction(ACTION_STOP));
    }
    @Override public IBinder onBind(Intent intent){return null;}
    private SharedPreferences prefs(){return getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE);}
    private void foreground(){
        NotificationManager nm=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(Build.VERSION.SDK_INT>=26&&nm!=null)nm.createNotificationChannel(
                new NotificationChannel("dns_takeover", "DNS Observer 接管状态",NotificationManager.IMPORTANCE_LOW));
        Notification.Builder n=new Notification.Builder(this,"dns_takeover")
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("DNS Observer · IPv4 / IPv6 DNS 接管")
                .setContentText("按选择的协议持续接管 · 可在应用内关闭")
                .setOngoing(true);
        startForeground(54,n.build());
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        String action=intent==null?"":intent.getAction();
        if(ACTION_STOP.equals(action)){
            stopped=true;uiPhase="stopping";DnsForwardService.cancelPendingStart();
            prefs().edit().putBoolean("takeover_enabled",false).commit();
            io.execute(this::stopAll);
            return START_NOT_STICKY;
        }
        if(!ACTION_START.equals(action) && !prefs().getBoolean("takeover_enabled",false)) {
            stopSelf();return START_NOT_STICKY;
        }
        try{foreground();}catch(Exception error){event(this,"无法启动前台服务："+error);uiPhase="idle";stopSelf();return START_NOT_STICKY;}
        stopped=false;
        if(!monitoring){
            monitoring=true;uiPhase="starting";
            io.execute(this::startSelected);
        }
        return START_STICKY;
    }
    private void status(String line){prefs().edit().putString("takeover_status",line).apply();event(this,line);}
    private Intent ipv4Intent(SharedPreferences p){
        Intent i=new Intent(this,DnsForwardService.class).setAction(DnsForwardService.ACTION_START);
        i.putExtra("host",p.getString("host",""));
        i.putExtra("port",parsePort(p.getString("port","31017")));
        i.putExtra("bootstrap",p.getString("bootstrap",""));
        i.putExtra("sub_host",p.getString("sub_host",""));
        i.putExtra("sub_port",parsePort(p.getString("sub_port","31017")));
        i.putExtra("secondary_host",p.getString("secondary_host",""));
        i.putExtra("secondary_port",parsePort(p.getString("secondary_port","31017")));
        i.putExtra("ipv6",false);
        return i;
    }
    private static int parsePort(String value){try{return Integer.parseInt(value);}catch(Exception ex){return -1;}}
    private void startSelected(){
        SharedPreferences p=prefs();
        expect4=p.getBoolean("takeover_ipv4",true);
        expect6=p.getBoolean("takeover_ipv6",false);
        fault4=false;fault6=false;
        ipv6EverActive=false;ipv6RepairBlocked=false;
        if(!expect4 && !expect6){status("没有勾选 IPv4/IPv6，未启动");uiPhase="idle";stopSelf();return;}
        if(stopped || !p.getBoolean("takeover_enabled",false)){stopAll();return;}
        boolean active6Now=false;
        try {
            // Never depend on Android's system resolver for hostname bootstrap.
            DnsBootstrap.parseLiteral(p.getString("bootstrap", "").trim());
            if(expect4){
                startForegroundService(ipv4Intent(p));
                status("IPv4 启动请求已发送；正在安装 NAT 接管规则");
            } else {
                try{DnsRootRules.remove(this);}catch(Exception ex){status("IPv4 清理失败："+ex.toString());}
            }
            if(stopped)return;
            if(expect6){
                String result=DnsIpv6GlobalController.start(this,()->!stopped&&prefs().getBoolean("takeover_enabled",false));
                if(stopped||!prefs().getBoolean("takeover_enabled",false))return;
                status("IPv6："+result);
                if(result.startsWith("IPv6 DNS53 已启用")){
                    ipv6EverActive=true;
                    active6Now=DnsIpv6GlobalController.active(this);
                    if(!active6Now)status("IPv6 启动校验已通过，但当前状态发生变化："+DnsIpv6GlobalController.lastCheckFailure());
                }else{
                    // A failed initial install is NOT a system takeover and must not
                    // trigger an endless 15-second reinstall/bind-conflict loop.
                    ipv6RepairBlocked=true;
                    status("IPv6 首次启动未成功：暂停本次会话的自动修复。请关闭接管并检查保留路由/监听端口。");
                }
            }else{
                status("IPv6 未勾选；本次不启动 IPv6 代理");
            }
            if(stopped||!prefs().getBoolean("takeover_enabled",false))return;
            status("接管启动检查：IPv4="+(!expect4?"未选择":DnsForwardService.isStarting()?"启动中":
                DnsForwardService.isServing()&&DnsRootRules.active(this)?"已启用":"未就绪，请查看服务状态")+
                "；IPv6="+(!expect6?"未选择":ipv6EverActive?(active6Now?"已启用":"启动曾通过，当前状态异常") :"启动失败，已暂停自动重试"));
        }catch(Exception ex){status("启动失败："+ex.getClass().getSimpleName()+" "+ex.getMessage());}
        if(!stopped)uiPhase="monitoring";
        Thread observer=new Thread(this::monitor,"DNS-takeover-observer");
        observer.setDaemon(true);observer.start();
    }
    private void monitor(){
        while(!stopped && prefs().getBoolean("takeover_enabled",false)){
            try{Thread.sleep(15000);}catch(InterruptedException e){Thread.currentThread().interrupt();break;}
            if(stopped || !prefs().getBoolean("takeover_enabled",false))break;
            // Root repair and stop share the same queue: a repair cannot install late rules
            // after stopAll has already reported cleanup complete.
            try{io.submit(this::checkAndRepair).get();}
            catch(InterruptedException ex){Thread.currentThread().interrupt();break;}
            catch(Exception ex){if(!stopped)event(this,"状态检查任务结束："+ex.toString());break;}
        }
    }
    private void checkAndRepair(){
        if(stopped||!prefs().getBoolean("takeover_enabled",false))return;
            SharedPreferences p=prefs(); boolean heal=p.getBoolean("takeover_auto_repair",false);
            if(expect4){
                boolean active=p.getBoolean("running",false)&&DnsRootRules.active(this);
                if(!active){
                    if(!fault4){status("DETECT: IPv4 DNS 接管被覆盖或服务退出");fault4=true;}
                    if(heal){
                        try{
                            if(!p.getBoolean("running",false))startForegroundService(ipv4Intent(p));
                            else DnsRootRules.install(this,false,"repair"+System.currentTimeMillis());
                            status("REPAIR: 已尝试重新接管 IPv4");
                        }catch(Exception ex){status("REPAIR_FAIL IPv4: "+ex.getMessage());}
                    }
                }else fault4=false;
            }
            if(stopped)return;
            if(expect6 && ipv6EverActive && !ipv6RepairBlocked){
                boolean active=DnsIpv6GlobalController.active(this);
                if(!active){
                    if(!fault6){status("DETECT: IPv6 曾正常运行，现检测到规则缺失或 Root 代理退出："+DnsIpv6GlobalController.lastCheckFailure());fault6=true;}
                    if(heal){
                        // One attempt per fault episode. Failed repair is latched,
                        // never retry indefinitely while a port or route is occupied.
                        ipv6RepairBlocked=true;
                        try{
                            String old=DnsIpv6GlobalController.stop(this);
                            status("IPv6 修复前清理："+old);
                            if(!old.contains("VERIFY_CLEAN")){
                                status("REPAIR_PAUSED IPv6: 自身规则清理未确认；禁止重试");
                            }else if(!stopped && prefs().getBoolean("takeover_enabled",false)){
                                String result=DnsIpv6GlobalController.start(this,()->!stopped&&prefs().getBoolean("takeover_enabled",false));
                                if(stopped||!prefs().getBoolean("takeover_enabled",false))return;
                                if(result.startsWith("IPv6 DNS53 已启用") && DnsIpv6GlobalController.active(this)){
                                    fault6=false;ipv6RepairBlocked=false;
                                    status("REPAIR_OK IPv6: 服务及规则已恢复");
                                }else status("REPAIR_PAUSED IPv6: "+result+"；本次会话停止重复修复");
                            }
                        }catch(Exception ex){status("REPAIR_PAUSED IPv6: "+ex.getMessage());}
                    }
                }else fault6=false;
            }
    }
    private void stopAll(){
        uiPhase="stopping";stopped=true;expect4=false;expect6=false;
        ipv6EverActive=false;ipv6RepairBlocked=true;
        StringBuilder b=new StringBuilder("关闭接管：");
        try{startService(new Intent(this,DnsForwardService.class).setAction(DnsForwardService.ACTION_STOP));
            b.append(" IPv4 服务停止请求已发出；");}catch(Exception ex){b.append(" IPv4 服务停止请求失败：").append(ex.toString());}
        try{DnsRootRules.remove(this);b.append(" IPv4 规则已清理；");}
        catch(Exception ex){b.append(" IPv4 清理失败：").append(ex.toString());}
        boolean clean6=false;
        try{String v6=DnsIpv6GlobalController.stop(this);b.append(" IPv6 ").append(v6).append('；');clean6=v6.contains("VERIFY_CLEAN");}
        catch(Exception ex){b.append(" IPv6 清理失败：").append(ex.toString());}
        try{DnsIpv6PilotController.stop(this);DnsIpv6Experiment.recover(this);b.append(" 旧实验规则已检查；");}
        catch(Exception ex){b.append(" 旧实验恢复失败：").append(ex.toString());}
        // A partially removed chain is not "active"; always verify complete absence.
        boolean clean4=false;
        for(int retry=0;retry<3&&!clean4;retry++) {
            try{
                DnsRootRules.remove(this);
                clean4=DnsRootRules.clean(this);
            }catch(Exception ex){
                if(retry==2)b.append(" IPv4 关闭校验未确认：").append(ex.toString());
                else try{Thread.sleep(200);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();break;}
            }
        }
        status(b.toString()+" IPv4="+(clean4?"VERIFY_CLEAN":"VERIFY_FAILED")+"，IPv6="+(clean6?"VERIFY_CLEAN":"VERIFY_FAILED/请核对恢复日志"));
        monitoring=false;uiPhase="idle";
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }
    @Override public void onDestroy(){stopped=true;uiPhase="idle";io.shutdown();super.onDestroy();}
}
