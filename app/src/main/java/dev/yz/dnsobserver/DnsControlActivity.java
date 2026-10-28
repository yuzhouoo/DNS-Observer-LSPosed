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
    private volatile boolean ipv6ExperimentRunning;
    private CheckBox ipv6;
    private TextView status, ipv6ExperimentResult;

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
    private void showExperimentLog(String result) {
        if(result==null)return;
        prefs.edit().putString("ipv6_last_report",result).apply();
        ipv6ExperimentResult.setText(result);
    }
    private SharedPreferences prefs;
    private boolean visible;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        prefs = getSharedPreferences(DnsForwardService.PREFS, MODE_PRIVATE);
        build();
        DnsUpstreamJob.schedule(this);
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
    private Button button(String title, LinearLayout root) {
        Button b=new Button(this);
        b.setText(title); b.setAllCaps(false);
        root.addView(b,new LinearLayout.LayoutParams(-1,dp(48)));
        return b;
    }
    private void build() {
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.setBackgroundColor(BG);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20),dp(16),dp(20),dp(24));scroll.addView(root);
        setContentView(scroll);
        root.addView(label("DNS 接管 · v0.5.5",23,FG));
        root.addView(label("保留现有 LSPosed DNS 监控；接管仅作用于常规 UDP/TCP 53。\n需要 Root。默认关闭、不随系统开机启动。",13,SECOND));
        status=selectable(label("正在检查状态…",15,FG));root.addView(status);
        button("复制当前接管状态",root).setOnClickListener(v->copyVisibleText(status,"接管状态"));
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
        ipv6=new CheckBox(this);ipv6.setText("同时重定向 IPv6 DNS（实验性，需 ip6tables NAT）");
        ipv6.setTextColor(FG);ipv6.setChecked(prefs.getBoolean("ipv6",false));
        root.addView(ipv6);
        root.addView(label("兼容性：IPv6 ip6tables NAT 不可用时，启动接管会明确降级为 IPv4-only，不影响独立 IPv6 测速。IPv6 TPROXY 需单独验证。",12,SECOND));
        root.addView(label("引导流程：优先系统 DNS 解析上游域名，失败时可使用备用纯 IP DNS。启用后只刷新上游地址，不修改系统 DNS 设置。",12,SECOND));
        root.addView(label("每个 IP 独立测速：ICMP Ping、UDP DNS、TCP DNS（IPv4/IPv6 分开）。\nPing 无响应不能直接判定 IP 不通，DNS 服务单独验证。",12,SECOND));
        button("开始主 / 从 / 备：Ping + UDP/TCP DNS 测速",root).setOnClickListener(v->testServer());
        speedResults=new LinearLayout(this);speedResults.setOrientation(LinearLayout.VERTICAL);
        root.addView(speedResults);
        speedResults.addView(label("未开始测速；点击上方按钮查看每个 IP 的独立延迟。",13,SECOND));
        root.addView(label("IPv6 TPROXY 分阶段实验：UDP/TCP 回环 + 本机非回环保留文档地址，仅使用特殊端口 15453 / 15454。不接管真实 DNS，35 秒自动清理并核对残留。",12,SECOND));
        ipv6ExperimentResult=selectable(label(
                prefs.getString("ipv6_last_report","IPv6 TPROXY 实验尚未运行。"),12,FG));
        root.addView(ipv6ExperimentResult);
        root.addView(label("实验日志可长按选择文本，也可点下面按钮一次复制完整原始输出。",12,SECOND));
        button("复制完整 IPv6 调试日志",root).setOnClickListener(v->copyVisibleText(ipv6ExperimentResult,"IPv6 调试日志"));
        button("验证 IPv6 TPROXY · UDP/TCP + 本机出站实验",root).setOnClickListener(v ->
            new AlertDialog.Builder(this).setTitle("运行 IPv6 TPROXY 隔离实验？")
                .setMessage("两阶段实验：先测试 IPv6 回环 UDP/TCP；成功后使用 UID、2001:db8:ffff::53 文档地址及15453端口的严格条件进行临时 OUTPUT 标记及专用路由表实验。仅新增自身规则，不修改原有规则，不接管 DNS 53；35 秒超时清理，并提供手动恢复及残留检查。运行前请停止 DNS 接管。")
                .setNegativeButton("取消",null)
                .setPositiveButton("开始验证",(d,w)-> {
                    if(ipv6ExperimentRunning){
                        status.setText("已有 IPv6 实验正在运行，请勿重复提交");
                        return;
                    }
                    ipv6ExperimentRunning=true;
                    new Thread(()->{
                        ui.post(()->{if(!isDestroyed())status.setText("IPv6 UDP/TCP 分阶段实验正在运行；上次日志仍可复制…");});
                        String result;
                        try{result=DnsIpv6Experiment.run(this);}
                        catch(Throwable t){result="IPv6 实验意外终止："+t.getClass().getSimpleName()+" "+t.getMessage();}
                        finally{ipv6ExperimentRunning=false;}
                        final String complete=result;
                        prefs.edit().putString("ipv6_last_report",complete).apply();
                        ui.post(()->{if(!isDestroyed())ipv6ExperimentResult.setText(complete);});
                    },"DNS-IPv6-experiment").start();
                }).show());
        button("一键恢复 IPv6 实验规则",root).setOnClickListener(v ->
            new Thread(()->{
                String outcome;
                try{outcome=DnsIpv6Experiment.recover(this);}
                catch(Exception e){outcome="实验规则恢复失败："+e.getMessage();}
                final String reply=outcome;
                ui.post(()->{
                    if(isDestroyed())return;
                    // Preserve the diagnostic details instead of replacing them with recovery output.
                    String existing=prefs.getString("ipv6_last_report","");
                    String combined=(existing.isEmpty()?"":existing+"\n\n")+"【手动恢复】\n"+reply;
                    showExperimentLog(combined);
                });
            },"DNS-IPv6-recover").start());
        button("启动 DNS 接管",root).setOnClickListener(v->new AlertDialog.Builder(this)
                .setTitle("启用 Root DNS 接管？")
                .setMessage("将重定向本机普通 UDP/TCP 53 请求。请确认你可以使用 KernelSU 或 Root 命令恢复网络。首次使用请关闭其它 DNS 重定向规则。")
                .setNegativeButton("取消",null).setPositiveButton("启用",(d,w)->startProxy()).show());
        button("关闭接管并恢复系统 DNS",root).setOnClickListener(v->{
            Intent stop=new Intent(this,DnsForwardService.class).setAction(DnsForwardService.ACTION_STOP);
            startService(stop);
            status.setText("正在停止并恢复原始 DNS 路径…");
        });
        button("紧急清理 Root 重定向规则",root).setOnClickListener(v->{
            // Request cancellation first so installation cannot race the cleanup.
            startService(new Intent(this,DnsForwardService.class)
                    .setAction(DnsForwardService.ACTION_STOP));
            new Thread(()->{
            try {
                DnsRootRules.remove(this);
                ui.post(()->status.setText("已发送 Root 规则清理命令。若仍有服务运行请点关闭接管。"));
            } catch(Exception e) {
                ui.post(()->status.setText("Root 清理失败："+e.getMessage()));
            }
        },"DNS-emergency").start();
        });
        root.addView(label("健康监测 · 每约 15 分钟在未接管时由系统调度，接管时每 60 秒测延时、每 5 分钟尝试刷新 IP。实际触发可能受系统省电影响；接管期间若未配置 Bootstrap 纯 IP，只监测已缓存地址。",12,SECOND));
        button("重新测速并保存全部 IP / 协议历史",root).setOnClickListener(v->testServer());
        root.addView(label("主从备测速 / IP 历史",17,FG));
        history=selectable(label("正在加载历史…",12,SECOND));root.addView(history);
        button("复制当前 DNS 测速历史",root).setOnClickListener(v->copyVisibleText(history,"DNS 测速历史"));
        root.addView(label("安全说明：本模块只清理 DOBSR53 专属防火墙链，不清空系统规则。单独的 Root 监视脚本会在应用进程消失时尝试回滚；无法保证所有 ROM / Root 实现上的绝对自动恢复。",12,SECOND));
    }
    private void persist() {
        prefs.edit().putString("host",host.getText().toString().trim())
                .putString("port",port.getText().toString().trim())
                .putString("bootstrap",bootstrap.getText().toString().trim())
                .putString("sub_host",subHost.getText().toString().trim())
                .putString("sub_port",subPort.getText().toString().trim())
                .putString("secondary_host",secondaryHost.getText().toString().trim())
                .putString("secondary_port",secondaryPort.getText().toString().trim())
                .putBoolean("ipv6",ipv6.isChecked()).apply();
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
        if(!b.isEmpty()) {
            try { DnsBootstrap.parseLiteral(b); } catch(Exception e) {throw new IllegalArgumentException("备用引导 DNS 必须是纯 IP");}
        }
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
            String hostname=checkedHost();int number=checkedPort();persist();
            Intent i=new Intent(this,DnsForwardService.class).setAction(DnsForwardService.ACTION_START);
            i.putExtra("host",hostname);i.putExtra("port",number);
            i.putExtra("bootstrap",bootstrap.getText().toString().trim());i.putExtra("ipv6",ipv6.isChecked());
            i.putExtra("sub_host",subHost.getText().toString().trim());
            i.putExtra("sub_port",subHost.getText().toString().trim().isEmpty()?31017:checkedExtraPort(subPort,"从 DNS"));
            i.putExtra("secondary_host",secondaryHost.getText().toString().trim());
            i.putExtra("secondary_port",secondaryHost.getText().toString().trim().isEmpty()?31017:
                    Integer.parseInt(secondaryPort.getText().toString().trim()));
            startForegroundService(i);
            status.setText("已提交启动任务，正在测试上游及安装专属规则…");
        } catch(Exception e){status.setText("配置错误："+e.getMessage());}
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
                card.addView(detailView);
                expanded.setOnClickListener(v->{
                    boolean open=detailView.getVisibility()!=View.VISIBLE;
                    detailView.setVisibility(open?View.VISIBLE:View.GONE);
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
                java.util.List<DnsDb.UpstreamEntry> checks=new DnsDb(this).latestUpstream(35);
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
                for(DnsDb.ProbeEntry entry:new DnsDb(this).latestProbes(80)) {
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
        if(at>0 && System.currentTimeMillis()-at<20000) {
            status.setText((p.getBoolean("running",false)?"● 正在接管：":"○ 未接管：")+p.getString("status",""));
        }
        if(history!=null && System.currentTimeMillis()-historyUpdated>15000) {
            historyUpdated=System.currentTimeMillis();refreshHistory();
        }
        ui.postDelayed(this,3500);
    }};
    @Override protected void onResume(){super.onResume();visible=true;ui.removeCallbacks(refresh);ui.postDelayed(refresh,1200);}
    @Override protected void onPause(){visible=false;ui.removeCallbacks(refresh);super.onPause();}
}
