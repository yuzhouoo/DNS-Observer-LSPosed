package dev.yz.dnsobserver;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.Switch;
import android.graphics.drawable.GradientDrawable;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;
import android.view.View;
import android.widget.Toast;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/** Manual controls only: opening the screen never modifies DNS or Root rules. */
public final class DnsControlActivity extends Activity {
    private static final int BG = Color.rgb(11,18,32), FG = Color.rgb(235,244,253);
    private static final int SECOND = Color.rgb(150,180,196);
    private final Handler ui = new Handler(Looper.getMainLooper());
    private EditText host, port, bootstrap, subHost, subPort, secondaryHost, secondaryPort;
    private TextView history;
    private LinearLayout speedResults;
    private volatile boolean measuring;
    private TextView status, ipv6PilotLog, ipv6GlobalLog, takeoverEvents;
    private CheckBox takeIpv4, takeIpv6;
    private Switch repairSwitch, bootSwitch, systemIpv6;
    private TextView ipv6Result;
    private boolean ipv6Busy;
    private ScrollView historyScroll;
    private Button speedHistoryToggle;
    private boolean historyExpanded;


    /** Text selection works with long press; the button copies the complete current result. */
    private TextView selectable(TextView view) {
        view.setTextIsSelectable(true);
        return view;
    }
    private void copyVisibleText(TextView view,String title) {
        if(view==null || view.getText()==null || view.getText().length()==0) {
            Toast.makeText(this,"暂无可复制的日志",Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager clipboard=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
        if(clipboard==null) {
            Toast.makeText(this,"无法访问剪贴板",Toast.LENGTH_SHORT).show();
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText(title,view.getText().toString()));
        Toast.makeText(this,"已复制完整"+title,Toast.LENGTH_SHORT).show();
    }
    private String pilotLog() { return DnsIpv6PilotController.report(this); }
    /** Keep the main page short; complete log is still in private preferences until cleared. */
    private void refreshPilotPreview() {
        if(ipv6PilotLog==null)return;
        String full=pilotLog();
        String[] lines=full.split("\n");
        StringBuilder tail=new StringBuilder();
        int first=Math.max(0,lines.length-6);
        if(first>0)tail.append("已折叠 ").append(first).append(" 行历史日志；点击查看完整内容。\n");
        for(int i=first;i<lines.length;i++)if(!lines[i].isEmpty())tail.append(lines[i]).append('\n');
        ipv6PilotLog.setText(tail.length()==0?"暂无试运行日志":tail.toString().trim());
    }
    private void refreshGlobalPreview() {
        if(ipv6GlobalLog!=null){
            String value=DnsIpv6GlobalController.report(this);
            if(!value.equals(ipv6GlobalLog.getText().toString()))
                ipv6GlobalLog.setText(value.isEmpty()?"暂无 IPv6 代理日志":value);
        }
    }
    private void showCompleteGlobalLog(){
        String value=DnsIpv6GlobalController.report(this);
        ScrollView scroll=new ScrollView(this);
        TextView detail=selectable(label(value.isEmpty()?"暂无日志":value,12,FG));
        detail.setPadding(dp(14),dp(12),dp(14),dp(12));scroll.addView(detail);
        new AlertDialog.Builder(this).setTitle("IPv6 全局接管 · 完整日志")
          .setView(scroll).setNeutralButton("复制全部",(d,w)->copyText(value,"IPv6 全局日志"))
          .setPositiveButton("关闭",null).show();
    }
    private void showCompletePilotLog() {
        String report=pilotLog();
        ScrollView scroll=new ScrollView(this);
        TextView full=selectable(label(report,12,FG));
        full.setPadding(dp(14),dp(12),dp(14),dp(12));
        scroll.addView(full);
        new AlertDialog.Builder(this).setTitle("IPv6 试运行 · 完整日志")
            .setView(scroll).setNeutralButton("复制全部",(d,w)->copyText(report,"IPv6 试运行日志"))
            .setPositiveButton("关闭",null).show();
    }
    private void copyText(String value,String title) {
        if(value==null||value.isEmpty()){
            Toast.makeText(this,"暂无可复制的日志",Toast.LENGTH_SHORT).show();return;
        }
        ClipboardManager clip=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
        if(clip==null){Toast.makeText(this,"无法访问剪贴板",Toast.LENGTH_SHORT).show();return;}
        clip.setPrimaryClip(ClipData.newPlainText(title,value));
        Toast.makeText(this,"已复制完整"+title,Toast.LENGTH_SHORT).show();
    }

    private SharedPreferences prefs;
    private boolean visible;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        prefs = getSharedPreferences(DnsForwardService.PREFS, MODE_PRIVATE);
        build();
        DnsUpstreamJob.schedule(this);
    }


    private void showIpv6State(String value) {
        systemIpv6.setOnCheckedChangeListener(null);
        systemIpv6.setChecked(value.startsWith("IPV6_DISABLED\n") || value.equals("IPV6_DISABLED"));
        systemIpv6.setOnCheckedChangeListener((b,on)->toggleIpv6FromUi(systemIpv6,ipv6Result,on));
    }
    private void refreshIpv6State() {
        if(ipv6Busy || systemIpv6==null)return;
        ipv6Busy=true;systemIpv6.setEnabled(false);
        new Thread(()->{
            String message;boolean success=false;
            try {message=Ipv6SystemToggle.status(getApplicationContext());success=true;}
            catch(Exception error){message="内核状态未知："+error;}
            final String output=message;final boolean ok=success;
            ui.post(()->{
                if(ok)showIpv6State(output);
                ipv6Result.setText(output);systemIpv6.setEnabled(true);ipv6Busy=false;
            });
        },"IPv6-system-status").start();
    }
    private void toggleIpv6FromUi(Switch control,TextView result,boolean disable) {
        if(ipv6Busy)return;
        ipv6Busy=true;control.setEnabled(false);result.setText("正在通过 Root 应用并验证…");
        new Thread(()->{
            String message;
            try {message=Ipv6SystemToggle.set(getApplicationContext(),disable);}
            catch(Exception error){message=error.toString();}
            String actual=null;
            try {actual=Ipv6SystemToggle.status(getApplicationContext());}
            catch(Exception error){message+="\n内核状态未知："+error;}
            final String output=message;final String verified=actual;
            ui.post(()->{
                if(verified!=null)showIpv6State(verified);
                result.setText(output+(verified==null?"":"\n当前内核状态：\n"+verified));
                control.setEnabled(true);ipv6Busy=false;
            });
        },"IPv6-system-toggle").start();
    }

    private int dp(int n) { return (int)(n*getResources().getDisplayMetrics().density+0.5f); }
    private TextView label(String text, int size, int color) {
        TextView l = new TextView(this);
        l.setText(text); l.setTextSize(size); l.setTextColor(color); l.setPadding(0,dp(7),0,dp(5));
        return l;
    }
    private EditText field(LinearLayout root, String title, String value) {
        root.addView(label(title,14,FG));
        EditText e = new EditText(this);
        e.setSingleLine(true);e.setTextSize(16);e.setTextColor(FG);e.setHintTextColor(SECOND);
        e.setText(value);e.setPadding(dp(8),dp(4),dp(8),dp(6));
        root.addView(e,new LinearLayout.LayoutParams(-1,dp(52)));
        return e;
    }
    private GradientDrawable surface(int color,int radius) {
        GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;
    }
    private ScrollView logArea(LinearLayout parent,TextView text,int height) {
        ScrollView box=new ScrollView(this);
        box.setFillViewport(false);box.setNestedScrollingEnabled(true);
        box.setBackground(surface(Color.rgb(20,32,51),12));
        text.setPadding(dp(12),dp(10),dp(12),dp(10));
        box.addView(text,new ScrollView.LayoutParams(-1,-2));
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,dp(height));
        lp.topMargin=dp(6);lp.bottomMargin=dp(8);
        parent.addView(box,lp);return box;
    }
    private Button button(String title, LinearLayout root) {
        Button b=new Button(this);
        b.setText(title);b.setAllCaps(false);b.setTextSize(14);b.setTextColor(FG);
        b.setBackground(surface(Color.rgb(34,57,80),10));
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,dp(46));
        lp.bottomMargin=dp(7);root.addView(b,lp);
        return b;
    }
    private void build() {
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.setBackgroundColor(BG);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16),dp(16),dp(16),dp(26));scroll.addView(root);
        setContentView(scroll);
        root.addView(label("DNS Observer · v"+BuildConfig.VERSION_NAME,23,FG));
        root.addView(label("IPv4 NAT / IPv6 TPROXY 独立选择 · 启用后不定时关闭 · Bootstrap-only",12,SECOND));
        status=selectable(label("正在检查接管状态…",14,FG));
        logArea(root,status,96);
        button("复制当前接管状态",root).setOnClickListener(v->copyVisibleText(status,"接管状态"));

        root.addView(label("系统网络 · IPv6 总开关（Root）",18,FG));
        root.addView(label("立即应用并校验全部接口及新接口默认值；关闭时恢复本次开机的原值。IPv6-only 网络可能断网；恢复地址需等待网络重新获取。",12,SECOND));
        systemIpv6=new Switch(this);
        systemIpv6.setText("禁用 IPv6（仅 IPv4）");systemIpv6.setTextColor(FG);
        systemIpv6.setEnabled(false);
        root.addView(systemIpv6);
        ipv6Result=selectable(label("正在读取内核状态…",12,SECOND));
        root.addView(ipv6Result);
        systemIpv6.setOnCheckedChangeListener((b,disable)->toggleIpv6FromUi(systemIpv6,ipv6Result,disable));
        button("刷新 IPv6 内核状态",root).setOnClickListener(v->refreshIpv6State());
        host=field(root,"主 DNS 域名（不带协议、端口）",prefs.getString("host",""));
        port=field(root,"主 DNS 端口",prefs.getString("port","31017"));
        port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        subHost=field(root,"从 DNS 域名（可留空）",prefs.getString("sub_host",""));
        subPort=field(root,"从 DNS 端口",prefs.getString("sub_port","31017"));
        subPort.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        secondaryHost=field(root,"备 DNS 域名（原备用 DNS，故障时使用）",prefs.getString("secondary_host",""));
        secondaryPort=field(root,"备 DNS 端口",prefs.getString("secondary_port","31017"));
        secondaryPort.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        bootstrap=field(root,"Bootstrap DNS 纯 IP（域名刷新使用，可留空）",prefs.getString("bootstrap",""));
        root.addView(label("接管协议",18,FG));
        LinearLayout types=new LinearLayout(this);types.setOrientation(LinearLayout.HORIZONTAL);
        takeIpv4=new CheckBox(this);takeIpv4.setText("IPv4");takeIpv4.setTextColor(FG);
        takeIpv4.setChecked(prefs.getBoolean("takeover_ipv4",true));
        takeIpv6=new CheckBox(this);takeIpv6.setText("IPv6");takeIpv6.setTextColor(FG);
        takeIpv6.setChecked(prefs.getBoolean("takeover_ipv6",false));
        types.addView(takeIpv4,new LinearLayout.LayoutParams(0,dp(48),1));
        types.addView(takeIpv6,new LinearLayout.LayoutParams(0,dp(48),1));root.addView(types);
        repairSwitch=new Switch(this);repairSwitch.setText("被系统覆盖后自动重新接管");
        repairSwitch.setTextColor(FG);repairSwitch.setChecked(prefs.getBoolean("takeover_auto_repair",false));
        root.addView(repairSwitch);
        repairSwitch.setOnCheckedChangeListener((b,on)->
            prefs.edit().putBoolean("takeover_auto_repair",on).apply());
        bootSwitch=new Switch(this);bootSwitch.setText("开机自动启动（仅上次保持接管开启时）");
        bootSwitch.setTextColor(FG);bootSwitch.setChecked(prefs.getBoolean("takeover_boot",false));
        root.addView(bootSwitch);
        bootSwitch.setOnCheckedChangeListener((b,on)->
            prefs.edit().putBoolean("takeover_boot",on).apply());
        root.addView(label("无定时恢复：手动关闭会强制清理 IPv4 和 IPv6（忽略勾选）。异常进程退出仍执行安全清理；覆盖自动重新接管仅在开关打开时执行。",12,SECOND));
        button("开启所选 IPv4 / IPv6 DNS 接管",root).setOnClickListener(v->
            new AlertDialog.Builder(this).setTitle("启动所选 DNS 接管？")
             .setMessage("启用后无固定到期时间。请确认 Bootstrap 纯 IP、Root 权限及紧急恢复方式；开启 IPv6 将影响普通非 Root UID 的 DNS53。")
             .setNegativeButton("取消",null).setPositiveButton("开启",(d,w)->startProxy()).show());
        button("关闭接管 · 强制清除 IPv4 / IPv6 所有规则",root).setOnClickListener(v->{
            DnsTakeoverService.requestStop(this);
            status.setText("已提交统一强制关闭，正在核对 IPv4/IPv6 规则…");
        });
        root.addView(label("覆盖检测及自动修复日志",17,FG));
        takeoverEvents=selectable(label("",12,FG));logArea(root,takeoverEvents,145);
        button("复制覆盖检测记录",root).setOnClickListener(v->copyText(DnsTakeoverService.events(this),"接管覆盖事件"));
        button("清空覆盖检测记录",root).setOnClickListener(v->{
            DnsTakeoverService.clearEvents(this);takeoverEvents.setText("暂无覆盖记录");
        });
        root.addView(label("主 / 从 / 备 · 引导解析和 UDP/TCP 诊断",17,FG));
        root.addView(label("所有主/从/备域名必须通过填写的 Bootstrap 纯 IP 查询，不再优先使用系统 DNS。",12,SECOND));
        button("开始主 / 从 / 备：Ping + UDP/TCP DNS 测速",root).setOnClickListener(v->testServer());
        speedResults=new LinearLayout(this);speedResults.setOrientation(LinearLayout.VERTICAL);
        ScrollView speedScroll=new ScrollView(this);speedScroll.setNestedScrollingEnabled(true);
        speedScroll.setBackground(surface(Color.rgb(20,32,51),12));
        speedScroll.addView(speedResults);root.addView(speedScroll,new LinearLayout.LayoutParams(-1,dp(190)));
        speedResults.addView(label("未开始测速；点击上方按钮检测各 IP。",13,SECOND));
        root.addView(label("IPv6 TPROXY Root 服务日志",17,FG));
        ipv6GlobalLog=selectable(label("",12,FG));logArea(root,ipv6GlobalLog,155);
        refreshGlobalPreview();
        button("复制 IPv6 全部日志",root).setOnClickListener(v->copyText(DnsIpv6GlobalController.report(this),"IPv6 日志"));
        button("清空 IPv6 日志",root).setOnClickListener(v->{DnsIpv6GlobalController.clearLog(this);refreshGlobalPreview();});
        button("查看 IPv6 规则状态",root).setOnClickListener(v->new Thread(()->{
            String result=DnsIpv6GlobalController.status(getApplicationContext());
            ui.post(()->status.setText(result));
        },"DNS-IPv6-status").start());
        root.addView(label("DNS 测速与 IP 变化历史",17,FG));
        speedHistoryToggle=button("展开最近测速历史",root);
        history=selectable(label("正在加载历史…",12,SECOND));
        historyScroll=logArea(root,history,190);historyScroll.setVisibility(View.GONE);
        speedHistoryToggle.setOnClickListener(v->{
            historyExpanded=!historyExpanded;
            historyScroll.setVisibility(historyExpanded?View.VISIBLE:View.GONE);
            speedHistoryToggle.setText(historyExpanded?"收起测速历史":"展开最近测速历史");
            if(historyExpanded)refreshHistory();
        });
        button("复制当前测速历史",root).setOnClickListener(v->copyVisibleText(history,"DNS 测速历史"));
        root.addView(label("高级诊断留存在底层代码；主页面已移除重复实验及冗余按钮。",12,SECOND));
    }
    private void persist() {
        prefs.edit().putString("host",host.getText().toString().trim())
                .putString("port",port.getText().toString().trim())
                .putString("bootstrap",bootstrap.getText().toString().trim())
                .putString("sub_host",subHost.getText().toString().trim())
                .putString("sub_port",subPort.getText().toString().trim())
                .putString("secondary_host",secondaryHost.getText().toString().trim())
                .putString("secondary_port",secondaryPort.getText().toString().trim())
                .putBoolean("ipv6",false)
                .putBoolean("takeover_ipv4",takeIpv4.isChecked())
                .putBoolean("takeover_ipv6",takeIpv6.isChecked())
                .putBoolean("takeover_auto_repair",repairSwitch.isChecked())
                .putBoolean("takeover_boot",bootSwitch.isChecked()).commit();
    }
    private int checkedPort() {
        String s=port.getText().toString().trim();
        int number=Integer.parseInt(s);
        if(number<=0||number>65535)throw new IllegalArgumentException("端口必须在 1~65535");
        return number;
    }
    private String checkedHost() {
        String name=host.getText().toString().trim();
        if(name.isEmpty()||name.contains("://")||name.contains("/")||name.contains(" ")||name.length()>253)
            throw new IllegalArgumentException("请填写纯域名，不含协议、端口或路径");
        String sub=subHost.getText().toString().trim();
        if(!sub.isEmpty() && (sub.contains("://")||sub.contains("/")||sub.contains(" ")||sub.length()>253))
            throw new IllegalArgumentException("从 DNS 必须是纯域名");
        if(!sub.isEmpty())checkedExtraPort(subPort,"从 DNS");
        String second=secondaryHost.getText().toString().trim();
        if(!second.isEmpty() && (second.contains("://")||second.contains("/")||second.contains(" ")||second.length()>253))
            throw new IllegalArgumentException("备用 DNS 必须是纯域名");
        if(!second.isEmpty())checkedExtraPort(secondaryPort,"备 DNS");
        String b=bootstrap.getText().toString().trim();
        try { DnsBootstrap.parseLiteral(b); }
        catch(Exception e) { throw new IllegalArgumentException("必须填写有效的引导 Bootstrap DNS 纯 IP"); }
        return name;
    }
    private int checkedExtraPort(EditText field,String role) {
        try {
            int p=Integer.parseInt(field.getText().toString().trim());
            if(p<1||p>65535)throw new NumberFormatException();
            return p;
        } catch(Exception e){throw new IllegalArgumentException(role+" 端口必须在 1~65535");}
    }
    private java.net.InetAddress[] knownIps(int role) {
        String raw=prefs.getString("role_ips_"+role,"");
        java.util.ArrayList<java.net.InetAddress> list=new java.util.ArrayList<>();
        for(String ip:raw.split(","))try {
            if(!ip.trim().isEmpty())list.add(DnsBootstrap.parseLiteral(ip.trim()));
        } catch(Exception ignored) { }
        return list.toArray(new java.net.InetAddress[0]);
    }
    private void startProxy() {
        try {
            checkedHost();checkedPort();
            if(!takeIpv4.isChecked()&&!takeIpv6.isChecked())
                throw new IllegalArgumentException("请至少勾选 IPv4 或 IPv6");
            persist();
            prefs.edit().putBoolean("takeover_enabled",true).commit();
            DnsTakeoverService.requestStart(this);
            status.setText("已提交接管启动，正在按勾选类型预检与安装规则…");
        } catch(Exception e){
            prefs.edit().putBoolean("takeover_enabled",false).commit();
            status.setText("配置或启动错误："+e.getMessage());
        }
    }
    private void testServer() {
        if(measuring){status.setText("正在进行测速，请勿重复提交");return;}
        final String[] domains=new String[3];
        final int[] ports=new int[3];
        final String bootstrapIp;
        final boolean active=prefs.getBoolean("running",false);
        try {
            domains[0]=checkedHost();ports[0]=checkedPort();
            domains[1]=subHost.getText().toString().trim();
            domains[2]=secondaryHost.getText().toString().trim();
            ports[1]=domains[1].isEmpty()?31017:checkedExtraPort(subPort,"从 DNS");
            ports[2]=domains[2].isEmpty()?31017:checkedExtraPort(secondaryPort,"备 DNS");
            bootstrapIp=bootstrap.getText().toString().trim();
            if(active && bootstrapIp.isEmpty()) {
                // Known per-role IPs are updated when the service starts/refreshed.
                for(int role=0;role<3;role++)if(!domains[role].isEmpty() && knownIps(role).length==0)
                    throw new IllegalArgumentException("接管中且未配置 Bootstrap；"+DnsFailover.NAMES[role]+" DNS 没有缓存 IP，请先停用接管再测速");
            }
            persist();
        } catch(Exception e){status.setText("测速配置错误："+e.getMessage());return;}
        measuring=true;
        status.setText("正在进行 IPv4/IPv6：ICMP Ping、UDP DNS、TCP DNS 分项检测…");
        new Thread(()->{
            UpstreamMonitor.Result[] results=new UpstreamMonitor.Result[3];
            try {
                for(int role=0;role<3;role++) {
                    if(domains[role].isEmpty())continue;
                    results[role]=UpstreamMonitor.check(this,DnsFailover.NAMES[role],domains[role],
                            ports[role],bootstrapIp,active,active?knownIps(role):null);
                }
            } catch(Throwable t) {
                android.util.Log.e("DNSObserver","DNS speed test unexpected failure",t);
            }
            ui.post(()->{
                measuring=false;
                if(isFinishing()||isDestroyed())return;
                renderSpeeds(domains,ports,results);
                status.setText("Ping / UDP DNS / TCP DNS 测速结束；详细诊断及历史已保存");
                refreshHistory();
            });
        },"DNS-speed-test").start();
    }
    private TextView speedCell(String title,String value) {
        TextView cell=label(title+"\n"+value,11,FG);
        cell.setPadding(dp(5),dp(9),dp(4),dp(9));
        cell.setBackgroundColor(Color.rgb(24,39,58));
        return cell;
    }
    private void renderSpeeds(String[] domains,int[] ports,UpstreamMonitor.Result[] values) {
        speedResults.removeAllViews();
        for(int role=0;role<3;role++) {
            LinearLayout card=new LinearLayout(this);card.setOrientation(LinearLayout.VERTICAL);
            card.setPadding(dp(10),dp(10),dp(10),dp(12));
            LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);
            lp.topMargin=dp(10);speedResults.addView(card,lp);
            card.setBackgroundColor(Color.rgb(20,33,50));
            final String title=DnsFailover.NAMES[role]+" DNS";
            if(domains[role].isEmpty()){
                card.addView(label(title+" · 未配置",16,SECOND));continue;
            }
            UpstreamMonitor.Result r=values[role];
            card.addView(label(title+" · "+domains[role]+":"+ports[role],16,FG));
            if(r==null){card.addView(label("测速未完成",12,SECOND));continue;}
            for(String family:new String[]{"IPv4","IPv6"}) {
                LinearLayout columns=new LinearLayout(this);
                LinearLayout.LayoutParams row=new LinearLayout.LayoutParams(-1,-2);row.topMargin=dp(5);
                card.addView(columns,row);
                for(String transport:new String[]{"PING","UDP","TCP"}) {
                    TextView cell=speedCell(family+" "+("PING".equals(transport)?"Ping":"DNS "+transport),r.summary(family,transport));
                    LinearLayout.LayoutParams cellLp=new LinearLayout.LayoutParams(0,-2,1);
                    cellLp.rightMargin=dp(3);
                    columns.addView(cell,cellLp);
                }
            }
            String details=r.detail();
            if(!r.error.isEmpty())card.addView(label("检测说明："+r.error,12,SECOND));
            if(!details.isEmpty()){
                TextView expanded=label("查看每个 IP 的 Ping / UDP DNS / TCP DNS 诊断（"+r.samples.size()+" 项）  ▾",12,SECOND);
                card.addView(expanded);
                TextView detailView=selectable(label(details,12,FG));
                detailView.setVisibility(View.GONE);
                ScrollView detailScroll=logArea(card,detailView,175);
                detailScroll.setVisibility(View.GONE);
                expanded.setOnClickListener(v->{
                    boolean open=detailView.getVisibility()!=View.VISIBLE;
                    detailScroll.setVisibility(open?View.VISIBLE:View.GONE);
                    expanded.setText(open?"收起该组 IP 诊断  ▴":"查看每个 IP 的 Ping / UDP DNS / TCP DNS 诊断（"+r.samples.size()+" 项）  ▾");
                });
                button("复制该组 IP 测速明细",card).setOnClickListener(v->copyVisibleText(detailView,title+" 测速明细"));
            }
        }
    }
    private void refreshHistory() {
        if(history==null)return;
        new Thread(()->{
            StringBuilder b=new StringBuilder();
            java.text.SimpleDateFormat fmt=new java.text.SimpleDateFormat("MM-dd HH:mm",java.util.Locale.getDefault());
            try {
                java.util.List<DnsDb.UpstreamEntry> checks=new DnsDb(this).latestUpstream(12);
                for(int i=0;i<checks.size();i++) {
                    DnsDb.UpstreamEntry item=checks.get(i);
                    boolean changed=false;
                    for(int n=i+1;n<checks.size();n++) {
                        DnsDb.UpstreamEntry old=checks.get(n);
                        if(old.role.equals(item.role)) {changed=!item.ips.isEmpty()&&!item.ips.equals(old.ips);break;}
                    }
                    b.append(fmt.format(new java.util.Date(item.ts))).append(" · ").append(item.role)
                     .append(item.success?" ● ":" ○ ").append(item.latency).append(" ms")
                     .append(changed?" · IP 变化":"").append("\n")
                     .append(item.host).append(" → ").append(item.ips.isEmpty()?"未知":item.ips)
                     .append(item.error.isEmpty()?"":" · "+item.error).append("\n\n");
                }
                b.append("— 最近逐 IP：Ping / UDP DNS / TCP DNS —\n");
                for(DnsDb.ProbeEntry entry:new DnsDb(this).latestProbes(18)) {
                    b.append(fmt.format(new java.util.Date(entry.ts))).append(' ').append(entry.role)
                     .append(' ').append(entry.family).append(' ')
                     .append("PING".equals(entry.transport)?"ICMP Ping":"DNS "+entry.transport).append(' ')
                     .append(entry.ip);
                    if(!"PING".equals(entry.transport)) b.append(':').append(entry.port);
                    b.append("  ").append(entry.success?(entry.latency<0?"成功，RTT 未取得":entry.latency+" ms"):
                            ("失败 · "+entry.error)).append('\n');
                }
            } catch(Exception e){b.append("历史读取失败：").append(e.getClass().getSimpleName());}
            String value=b.length()==0?"暂无检测历史":b.toString();
            ui.post(()->{if(history!=null)history.setText(value);});
        },"DNS-history").start();
    }
    private long historyUpdated;
    private final Runnable refresh=new Runnable(){@Override public void run(){
        if(!visible)return;
        // Do not overwrite active diagnostic messages while user is editing/testing.
        SharedPreferences p=getSharedPreferences(DnsForwardService.PREFS, MODE_PRIVATE);
        long at=p.getLong("updated",0);
        String report=p.getString("takeover_status","");
        if(!report.isEmpty()){
            String current=(p.getBoolean("takeover_enabled",false)?"● 接管已请求：":"○ 接管已关闭：")+report;
            if(!current.equals(status.getText().toString()))status.setText(current);
        }
        if(historyExpanded && history!=null && System.currentTimeMillis()-historyUpdated>15000) {
            historyUpdated=System.currentTimeMillis();refreshHistory();
        }
        if(takeoverEvents!=null){
            String value=DnsTakeoverService.events(DnsControlActivity.this);
            if(!value.equals(takeoverEvents.getText().toString()))
                takeoverEvents.setText(value.isEmpty()?"暂无覆盖记录":value);
        }
        refreshGlobalPreview();
        ui.postDelayed(this,3500);
    }};
    @Override protected void onResume(){super.onResume();visible=true;refreshIpv6State();ui.removeCallbacks(refresh);ui.postDelayed(refresh,1200);}
    @Override protected void onPause(){visible=false;ui.removeCallbacks(refresh);super.onPause();}
}
