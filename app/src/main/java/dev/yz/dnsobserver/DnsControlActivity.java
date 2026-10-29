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
    private static volatile boolean measuring;
    private static volatile String speedMessage="测速：未开始";
    private TextView status, ipv6PilotLog, ipv6GlobalLog, takeoverEvents;
    private CheckBox takeIpv4, takeIpv6;
    private Switch repairSwitch, bootSwitch, systemIpv6;
    private TextView ipv6Result;
    private static volatile boolean ipv6Busy;
    private boolean checkingFeatures, ruleBusy;
    private Button startButton,stopButton,speedButton,ruleButton,ipv6Refresh,featureRefresh;
    private TextView featureOverview,selectionHint,speedStatus,featureStamp;
    private DnsUiSnapshot snapshot;
    private long checkedAt,pendingAt;
    private int snapshotVersion;
    private String pendingPhase="";
    private boolean startDialogOpen;
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


    private String phase() {
        String actual=DnsTakeoverService.uiPhase();
        if(!"idle".equals(actual)){pendingPhase="";return actual;}
        if(!pendingPhase.isEmpty() && android.os.SystemClock.elapsedRealtime()-pendingAt<5000)return pendingPhase;
        pendingPhase="";return actual;
    }
    private void setPending(String value) {
        pendingPhase=value;pendingAt=android.os.SystemClock.elapsedRealtime();
        snapshotVersion++;checkedAt=0;renderFeatureStates();
    }
    private void showIpv6State(String value) {
        systemIpv6.setOnCheckedChangeListener(null);
        systemIpv6.setChecked(value.startsWith("IPV6_DISABLED\n") || value.equals("IPV6_DISABLED"));
        systemIpv6.setOnCheckedChangeListener((b,on)->toggleIpv6FromUi(systemIpv6,ipv6Result,on));
    }
    private void refreshIpv6State() { refreshFeatureStates(); }
    private void refreshFeatureStates() {
        renderFeatureStates();
        String current=phase();
        if(checkingFeatures || ipv6Busy || "starting".equals(current)||"stopping".equals(current))return;
        checkingFeatures=true;renderFeatureStates();
        final int version=snapshotVersion;
        new Thread(()->{
            DnsUiSnapshot value=DnsUiSnapshot.read(getApplicationContext());
            ui.post(()->{
                checkingFeatures=false;
                if(isFinishing()||isDestroyed())return;
                if(version==snapshotVersion){snapshot=value;checkedAt=android.os.SystemClock.elapsedRealtime();}
                renderFeatureStates();
            });
        },"DNS-feature-status").start();
    }
    private void paint(Button button,String title,boolean enabled,boolean danger) {
        if(button==null)return;
        button.setText(title);button.setEnabled(enabled);button.setAlpha(enabled?1f:0.45f);
        button.setBackground(surface(danger?Color.rgb(111,43,53):Color.rgb(34,57,80),10));
    }
    private void renderFeatureStates() {
        if(featureOverview==null)return;
        if(speedStatus!=null)speedStatus.setText(speedMessage);
        String current=phase();
        boolean requested=prefs.getBoolean("takeover_enabled",false);
        boolean fresh=snapshot!=null && checkedAt>0 && android.os.SystemClock.elapsedRealtime()-checkedAt<20000;
        String system=fresh?snapshot.system:"unknown";
        boolean selected4=prefs.getBoolean("takeover_ipv4",true),selected6=prefs.getBoolean("takeover_ipv6",false);
        DnsFeatureState v4=DnsFeatureState.resolve(!"stopping".equals(current)&&DnsForwardService.isStarting()?"starting":current,selected4,requested,
            fresh&&!"unknown".equals(snapshot.v4),fresh&&"present".equals(snapshot.v4),fresh&&snapshot.active4);
        DnsFeatureState v6=DnsFeatureState.resolve(!"stopping".equals(current)&&DnsIpv6GlobalController.isStarting()?"starting":current,selected6,requested,
            fresh&&!"unknown".equals(snapshot.v6),fresh&&"present".equals(snapshot.v6),fresh&&snapshot.active6);
        SharedPreferences record=getSharedPreferences(SecureProvider.PREFS,MODE_PRIVATE);
        boolean enabled=record.getBoolean("enabled",true);
        long hb=record.getLong("heartbeat",0);
        boolean live=hb>0 && System.currentTimeMillis()-hb<25000;
        String records=!enabled?"已暂停":live?"记录中":"已开启，系统端未连接";
        String systemLabel=ipv6Busy?"正在应用并校验":
            "disabled".equals(system)?"已禁用 · 仅 IPv4":
            "enabled".equals(system)?"未禁用 · 接口允许 IPv6":
            "mixed".equals(system)?"部分接口禁用 · 非全局禁用":"待确认 · 请刷新状态";
        featureOverview.setText("DNS 记录："+records+"\nIPv4 DNS 接管："+v4.label+
            "\nIPv6 DNS 接管："+v6.label+"\n系统 IPv6："+systemLabel+
            "\n自动重新接管："+(repairSwitch!=null&&repairSwitch.isChecked()?"已开启":"已关闭")+
            "\n开机自动接管："+(bootSwitch!=null&&bootSwitch.isChecked()?(requested?"已开启，等待下次开机":"已开启；手动关闭后不自动启动"):"已关闭"));
        featureOverview.setTextColor(v4==DnsFeatureState.ERROR||v6==DnsFeatureState.ERROR?Color.rgb(255,170,112):FG);
        String stamp=checkedAt==0?"尚未完成本次状态校验":
            "最近校验："+new java.text.SimpleDateFormat("HH:mm:ss",java.util.Locale.getDefault()).format(
                new java.util.Date(System.currentTimeMillis()-(android.os.SystemClock.elapsedRealtime()-checkedAt)));
        featureStamp.setText((checkingFeatures?"正在核对内核与代理… · ":"")+stamp+
            (fresh&&!snapshot.error.isEmpty()?"\n"+snapshot.error:"")+(!fresh&&checkedAt>0?" · 结果已过期":""));
        boolean lifecycleBusy="starting".equals(current)||"stopping".equals(current);
        boolean session=requested || !"idle".equals(current) || (fresh&&(snapshot.active4||snapshot.active6));
        boolean lockConfig=session||lifecycleBusy||ipv6Busy||measuring;
        for(EditText field:new EditText[]{host,port,bootstrap,subHost,subPort,secondaryHost,secondaryPort})
            if(field!=null){field.setEnabled(!lockConfig);field.setAlpha(lockConfig?0.55f:1f);}
        if(takeIpv4!=null){takeIpv4.setEnabled(!lockConfig);takeIpv6.setEnabled(!lockConfig);}
        String selected=takeIpv4==null?"":(takeIpv4.isChecked()?"IPv4 ":"")+(takeIpv6.isChecked()?"IPv6":"");
        if(selectionHint!=null)selectionHint.setText(session?"接管会话运行中：请先关闭接管，再修改 DNS 和协议配置。":
            "下次启动配置："+(selected.isEmpty()?"未选择协议":selected)+"。勾选不会立即开启接管。");
        boolean configReady=false;String configError="";
        if(takeIpv4!=null)try{checkedHost();checkedPort();configReady=true;}
        catch(Exception error){configError=error.getMessage();}
        if(!session && selectionHint!=null && !configReady)selectionHint.append("\n配置待完善："+configError);
        boolean canStart=takeIpv4!=null&&DnsFeatureState.mayStart(requested,current,ipv6Busy||measuring||checkingFeatures,
            configReady,takeIpv4.isChecked(),takeIpv6.isChecked(),v4,v6,system);
        String startTitle="starting".equals(current)?"正在开启接管…":
            "stopping".equals(current)?"正在关闭，请稍候…":session?"接管会话已请求 · 查看各协议校验状态":
            checkingFeatures?"正在核对状态…":!fresh?"请先刷新状态":
            v4!=DnsFeatureState.OFF||v6!=DnsFeatureState.OFF?"状态异常或未确认 · 请先检查 / 清理":
            takeIpv6!=null&&takeIpv6.isChecked()&&("disabled".equals(system)||"unknown".equals(system))?"请先恢复系统 IPv6，再启用 IPv6 接管":
            !configReady?"请完善 DNS / 端口 / Bootstrap 配置":selected.isEmpty()?"请先选择接管协议":"开启所选 DNS 接管";
        paint(startButton,startTitle,canStart,false);
        boolean clean=fresh&&v4==DnsFeatureState.OFF&&v6==DnsFeatureState.OFF&&!session;
        paint(stopButton,"stopping".equals(current)?"正在关闭并校验清理结果…":
            clean?"接管已关闭 · 无需清理":session?"关闭全部 DNS 接管":"检查并清理残留接管",!clean&&!"stopping".equals(current)&&!ipv6Busy,true);
        boolean v6Conflict=takeIpv6!=null && (session&&selected6 || fresh&&"present".equals(snapshot.v6));
        systemIpv6.setEnabled(fresh&&!"unknown".equals(system)&&!checkingFeatures&&!ipv6Busy&&!lifecycleBusy&&!measuring&&!v6Conflict);
        if(!ipv6Busy){
            systemIpv6.setOnCheckedChangeListener(null);systemIpv6.setChecked("disabled".equals(system));
            systemIpv6.setOnCheckedChangeListener((b,on)->toggleIpv6FromUi(systemIpv6,ipv6Result,on));
        }
        systemIpv6.setText(ipv6Busy?"系统 IPv6 · 处理中…":v6Conflict?"禁用 IPv6 · 请先关闭 IPv6 接管":
            "disabled".equals(system)?"禁用 IPv6 · 已开启（仅 IPv4）":"禁用 IPv6 · "+("unknown".equals(system)?"待确认":"未开启"));
        paint(ipv6Refresh,checkingFeatures?"正在核对 IPv6 状态…":"刷新 IPv6 内核状态",!checkingFeatures&&!ipv6Busy&&!lifecycleBusy,false);
        paint(featureRefresh,checkingFeatures?"正在刷新所有功能状态…":"刷新所有功能状态",!checkingFeatures&&!ipv6Busy&&!lifecycleBusy,false);
        paint(speedButton,measuring?"正在测速… · 请等待结果":"开始主 / 从 / 备测速",!measuring&&!ipv6Busy&&!lifecycleBusy,false);
        paint(ruleButton,ruleBusy?"正在读取 IPv6 规则…":"查看 IPv6 规则详情",!ruleBusy&&!ipv6Busy&&!lifecycleBusy,false);
        if(repairSwitch!=null)repairSwitch.setText("自动重新接管 · "+(repairSwitch.isChecked()?"已开启":"已关闭"));
        if(bootSwitch!=null)bootSwitch.setText("开机自动接管 · "+(bootSwitch.isChecked()?"已开启":"已关闭"));
    }
    private void toggleIpv6FromUi(Switch control,TextView result,boolean disable) {
        if(ipv6Busy)return;
        ipv6Busy=true;snapshotVersion++;checkedAt=0;
        result.setText("正在通过 Root 应用并验证…");renderFeatureStates();
        new Thread(()->{
            String message;
            try {message=Ipv6SystemToggle.set(getApplicationContext(),disable);}
            catch(Exception error){message=error.toString();}
            String actual=null;
            try {actual=Ipv6SystemToggle.status(getApplicationContext());}
            catch(Exception error){message+="\n内核状态未知："+error;}
            final String output=message;final String verified=actual;
            ui.post(()->{
                ipv6Busy=false;
                if(isFinishing()||isDestroyed())return;
                if(verified!=null)showIpv6State(verified);
                result.setText(output+(verified==null?"":"\n当前内核状态：\n"+verified));
                ipv6Busy=false;refreshFeatureStates();
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
        b.setBackground(surface(Color.rgb(34,57,80),10));b.setMinHeight(dp(48));b.setPadding(dp(10),dp(8),dp(10),dp(8));
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);
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
        featureOverview=selectable(label("正在核对各功能状态…",15,FG));
        logArea(root,featureOverview,210);
        featureStamp=label("尚未完成状态校验",12,SECOND);root.addView(featureStamp);
        featureRefresh=button("刷新所有功能状态",root);featureRefresh.setOnClickListener(v->refreshFeatureStates());
        root.addView(label("最近操作与接管事件",14,SECOND));
        status=selectable(label("暂无操作",14,FG));
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
        ipv6Refresh=button("刷新 IPv6 内核状态",root);ipv6Refresh.setOnClickListener(v->refreshIpv6State());
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
        root.addView(label("下次启动的接管协议",18,FG));
        selectionHint=label("勾选仅配置下次启动，不代表已开启",12,SECOND);root.addView(selectionHint);
        LinearLayout types=new LinearLayout(this);types.setOrientation(LinearLayout.HORIZONTAL);
        takeIpv4=new CheckBox(this);takeIpv4.setText("IPv4");takeIpv4.setTextColor(FG);
        takeIpv4.setChecked(prefs.getBoolean("takeover_ipv4",true));
        takeIpv6=new CheckBox(this);takeIpv6.setText("IPv6");takeIpv6.setTextColor(FG);
        takeIpv6.setChecked(prefs.getBoolean("takeover_ipv6",false));
        takeIpv4.setOnCheckedChangeListener((b,on)->renderFeatureStates());
        takeIpv6.setOnCheckedChangeListener((b,on)->renderFeatureStates());
        types.addView(takeIpv4,new LinearLayout.LayoutParams(0,dp(48),1));
        types.addView(takeIpv6,new LinearLayout.LayoutParams(0,dp(48),1));root.addView(types);
        repairSwitch=new Switch(this);repairSwitch.setText("被系统覆盖后自动重新接管");
        repairSwitch.setTextColor(FG);repairSwitch.setChecked(prefs.getBoolean("takeover_auto_repair",false));
        root.addView(repairSwitch);
        repairSwitch.setOnCheckedChangeListener((b,on)->
            {prefs.edit().putBoolean("takeover_auto_repair",on).apply();renderFeatureStates();});
        bootSwitch=new Switch(this);bootSwitch.setText("开机自动启动（仅上次保持接管开启时）");
        bootSwitch.setTextColor(FG);bootSwitch.setChecked(prefs.getBoolean("takeover_boot",false));
        root.addView(bootSwitch);
        bootSwitch.setOnCheckedChangeListener((b,on)->
            {prefs.edit().putBoolean("takeover_boot",on).apply();renderFeatureStates();});
        root.addView(label("无定时恢复：手动关闭会强制清理 IPv4 和 IPv6（忽略勾选）。异常进程退出仍执行安全清理；覆盖自动重新接管仅在开关打开时执行。",12,SECOND));
        startButton=button("正在核对接管状态…",root);startButton.setEnabled(false);
        startButton.setOnClickListener(v->{
            if(startDialogOpen || !startButton.isEnabled())return;
            startDialogOpen=true;
            AlertDialog dialog=new AlertDialog.Builder(this).setTitle("开启所选 DNS 接管？")
             .setMessage("本次将启用："+(takeIpv4.isChecked()?"IPv4 ":"")+(takeIpv6.isChecked()?"IPv6":"")+
                "。保持运行直到手动关闭；以页面上各协议的校验状态为准。")
             .setNegativeButton("取消",null).setPositiveButton("开启",(d,w)->startProxy()).create();
            dialog.setOnDismissListener(d->startDialogOpen=false);dialog.show();
        });
        stopButton=button("检查并清理残留接管",root);
        stopButton.setOnClickListener(v->{
            try {
                setPending("stopping");DnsTakeoverService.requestStop(this);
                status.setText("已提交统一强制关闭，正在核对 IPv4/IPv6 规则…");
            }catch(Exception error){pendingPhase="";status.setText("提交关闭失败："+error.getMessage());refreshFeatureStates();}
        });
        root.addView(label("覆盖检测及自动修复日志",17,FG));
        takeoverEvents=selectable(label("",12,FG));logArea(root,takeoverEvents,145);
        button("复制覆盖检测记录",root).setOnClickListener(v->copyText(DnsTakeoverService.events(this),"接管覆盖事件"));
        button("清空覆盖检测记录",root).setOnClickListener(v->{
            new AlertDialog.Builder(this).setTitle("清空覆盖检测记录？").setMessage("仅清空日志，不关闭接管。")
                .setNegativeButton("取消",null).setPositiveButton("清空",(d,w)->{
                    DnsTakeoverService.clearEvents(this);takeoverEvents.setText("暂无覆盖记录");
                    Toast.makeText(this,"覆盖检测记录已清空",Toast.LENGTH_SHORT).show();
                }).show();
        });
        root.addView(label("主 / 从 / 备 · 引导解析和 UDP/TCP 诊断",17,FG));
        root.addView(label("所有主/从/备域名必须通过填写的 Bootstrap 纯 IP 查询，不再优先使用系统 DNS。",12,SECOND));
        speedStatus=label("测速：未开始",12,SECOND);root.addView(speedStatus);
        speedButton=button("开始主 / 从 / 备测速",root);speedButton.setOnClickListener(v->testServer());
        speedResults=new LinearLayout(this);speedResults.setOrientation(LinearLayout.VERTICAL);
        ScrollView speedScroll=new ScrollView(this);speedScroll.setNestedScrollingEnabled(true);
        speedScroll.setBackground(surface(Color.rgb(20,32,51),12));
        speedScroll.addView(speedResults);root.addView(speedScroll,new LinearLayout.LayoutParams(-1,dp(190)));
        speedResults.addView(label("未开始测速；点击上方按钮检测各 IP。",13,SECOND));
        root.addView(label("IPv6 TPROXY Root 服务日志",17,FG));
        ipv6GlobalLog=selectable(label("",12,FG));logArea(root,ipv6GlobalLog,155);
        refreshGlobalPreview();
        button("复制 IPv6 全部日志",root).setOnClickListener(v->copyText(DnsIpv6GlobalController.report(this),"IPv6 日志"));
        button("清空 IPv6 日志",root).setOnClickListener(v->new AlertDialog.Builder(this)
            .setTitle("清空 IPv6 日志？").setMessage("仅清空日志，不关闭 IPv6 接管。")
            .setNegativeButton("取消",null).setPositiveButton("清空",(d,w)->{
                DnsIpv6GlobalController.clearLog(this);refreshGlobalPreview();
                Toast.makeText(this,"IPv6 日志已清空",Toast.LENGTH_SHORT).show();
            }).show());
        ruleButton=button("查看 IPv6 规则详情",root);
        ruleButton.setOnClickListener(v->{
            if(ruleBusy)return;ruleBusy=true;renderFeatureStates();
            new Thread(()->{
                String value=DnsIpv6GlobalController.status(getApplicationContext());
                ui.post(()->{
                    ruleBusy=false;if(isFinishing()||isDestroyed())return;renderFeatureStates();
                    ScrollView box=new ScrollView(this);TextView detail=selectable(label(value,12,FG));
                    detail.setPadding(dp(14),dp(12),dp(14),dp(12));box.addView(detail);
                    new AlertDialog.Builder(this).setTitle("IPv6 规则详情").setView(box)
                        .setNeutralButton("复制",(d,w)->copyText(value,"IPv6 规则详情")).setPositiveButton("关闭",null).show();
                });
            },"DNS-IPv6-status").start();
        });
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
        android.text.TextWatcher watcher=new android.text.TextWatcher(){
            public void beforeTextChanged(CharSequence t,int st,int count,int after){}
            public void onTextChanged(CharSequence t,int st,int before,int count){renderFeatureStates();}
            public void afterTextChanged(android.text.Editable e){}
        };
        for(EditText field:new EditText[]{host,port,bootstrap,subHost,subPort,secondaryHost,secondaryPort})field.addTextChangedListener(watcher);
        renderFeatureStates();
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
            if(takeIpv6.isChecked() && (snapshot==null || "disabled".equals(snapshot.system) || "unknown".equals(snapshot.system)))
                throw new IllegalArgumentException("请先恢复系统 IPv6，并刷新状态");
            persist();
            setPending("starting");
            prefs.edit().putBoolean("takeover_enabled",true).commit();
            DnsTakeoverService.requestStart(this);
            status.setText("已提交接管启动，正在按勾选类型预检与安装规则…");
        } catch(Exception e){
            prefs.edit().putBoolean("takeover_enabled",false).commit();
            pendingPhase="";status.setText("配置或启动错误："+e.getMessage());
            refreshFeatureStates();
        }
    }
    private void testServer() {
        if(measuring)return;
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
        } catch(Exception e){speedMessage="测速：配置错误 · "+e.getMessage();speedStatus.setText(speedMessage);return;}
        measuring=true;renderFeatureStates();
        speedMessage="测速：进行中 · Ping / UDP DNS / TCP DNS，请稍候…";speedStatus.setText(speedMessage);
        new Thread(()->{
            UpstreamMonitor.Result[] results=new UpstreamMonitor.Result[3];
            String failure=null;
            try {
                for(int role=0;role<3;role++) {
                    if(domains[role].isEmpty())continue;
                    results[role]=UpstreamMonitor.check(this,DnsFailover.NAMES[role],domains[role],
                            ports[role],bootstrapIp,active,active?knownIps(role):null);
                }
            } catch(Throwable t) {
                android.util.Log.e("DNSObserver","DNS speed test unexpected failure",t);
                failure=t.getClass().getSimpleName();
            }
            final String error=failure;
            ui.post(()->{
                measuring=false;speedMessage=error==null?"测速：已完成 · 各 IP 成败见下方诊断 / 历史":"测速：异常终止 · "+error;
                if(isFinishing()||isDestroyed())return;
                renderSpeeds(domains,ports,results);
                speedStatus.setText(speedMessage);
                renderFeatureStates();
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
            String current="最近接管事件："+report;
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
        refreshFeatureStates();
        ui.postDelayed(this,5000);
    }};
    @Override protected void onResume(){super.onResume();visible=true;refreshIpv6State();ui.removeCallbacks(refresh);ui.postDelayed(refresh,1200);}
    @Override protected void onPause(){visible=false;ui.removeCallbacks(refresh);super.onPause();}
}
