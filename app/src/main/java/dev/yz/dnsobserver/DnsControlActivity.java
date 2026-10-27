package dev.yz.dnsobserver;

import android.app.Activity;
import android.app.AlertDialog;
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

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/** Manual controls only: opening the screen never modifies DNS or Root rules. */
public final class DnsControlActivity extends Activity {
    private static final int BG = Color.rgb(11,18,32), FG = Color.rgb(235,244,253);
    private static final int SECOND = Color.rgb(150,180,196);
    private final Handler ui = new Handler(Looper.getMainLooper());
    private EditText host, port, bootstrap, secondaryHost, secondaryPort;
    private TextView history;
    private CheckBox ipv6;
    private TextView status;
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
        root.addView(label("DNS 接管 · v0.4.0",23,FG));
        root.addView(label("保留现有 LSPosed DNS 监控；接管仅作用于常规 UDP/TCP 53。\n需要 Root。默认关闭、不随系统开机启动。",13,SECOND));
        status=label("正在检查状态…",15,FG);root.addView(status);
        host=field(root,"上游 DNS 域名（不带协议、端口）",prefs.getString("host",""));
        port=field(root,"上游 DNS 端口",prefs.getString("port","31017"));
        port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        secondaryHost=field(root,"备用上游 DNS 域名（故障时使用，可留空）",prefs.getString("secondary_host",""));
        secondaryPort=field(root,"备用上游端口",prefs.getString("secondary_port","31017"));
        secondaryPort.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        bootstrap=field(root,"Bootstrap DNS 纯 IP（域名刷新使用，可留空）",prefs.getString("bootstrap",""));
        ipv6=new CheckBox(this);ipv6.setText("同时重定向 IPv6 DNS（实验性，需 ip6tables NAT）");
        ipv6.setTextColor(FG);ipv6.setChecked(prefs.getBoolean("ipv6",false));
        root.addView(ipv6);
        root.addView(label("引导流程：优先系统 DNS 解析上游域名，失败时可使用备用纯 IP DNS。启用后只刷新上游地址，不修改系统 DNS 设置。",12,SECOND));
        button("检测上游 UDP/TCP DNS（不需要 Root）",root).setOnClickListener(v->testServer());
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
        button("立即检测主备 DNS 并写入历史",root).setOnClickListener(v->testServer());
        root.addView(label("上游检测与 IP 历史",17,FG));
        history=label("正在加载历史…",12,SECOND);root.addView(history);
        root.addView(label("安全说明：本模块只清理 DOBSR53 专属防火墙链，不清空系统规则。单独的 Root 监视脚本会在应用进程消失时尝试回滚；无法保证所有 ROM / Root 实现上的绝对自动恢复。",12,SECOND));
    }
    private void persist() {
        prefs.edit().putString("host",host.getText().toString().trim())
                .putString("port",port.getText().toString().trim())
                .putString("bootstrap",bootstrap.getText().toString().trim())
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
        String second=secondaryHost.getText().toString().trim();
        if(!second.isEmpty() && (second.contains("://")||second.contains("/")||second.contains(" ")||second.length()>253))
            throw new IllegalArgumentException("备用 DNS 必须是纯域名");
        if(!second.isEmpty()) {
            try {int p=Integer.parseInt(secondaryPort.getText().toString().trim());if(p<1||p>65535)throw new Exception();}
            catch(Exception e){throw new IllegalArgumentException("备用端口必须在 1~65535");}
        }
        String b=bootstrap.getText().toString().trim();
        if(!b.isEmpty()) {
            try { DnsBootstrap.parseLiteral(b); } catch(Exception e) {throw new IllegalArgumentException("备用引导 DNS 必须是纯 IP");}
        }
        return name;
    }
    private void startProxy() {
        try {
            String hostname=checkedHost();int number=checkedPort();persist();
            Intent i=new Intent(this,DnsForwardService.class).setAction(DnsForwardService.ACTION_START);
            i.putExtra("host",hostname);i.putExtra("port",number);
            i.putExtra("bootstrap",bootstrap.getText().toString().trim());i.putExtra("ipv6",ipv6.isChecked());
            i.putExtra("secondary_host",secondaryHost.getText().toString().trim());
            i.putExtra("secondary_port",secondaryHost.getText().toString().trim().isEmpty()?31017:
                    Integer.parseInt(secondaryPort.getText().toString().trim()));
            startForegroundService(i);
            status.setText("已提交启动任务，正在测试上游及安装专属规则…");
        } catch(Exception e){status.setText("配置错误："+e.getMessage());}
    }
    private void testServer() {
        if (prefs.getBoolean("running", false)) {
            status.setText("请先停止接管再检测，避免在接管过程中调用系统 Bootstrap DNS");
            return;
        }
        final String name;
        final String backup;
        final int upstreamPort;
        try {name=checkedHost();upstreamPort=checkedPort();backup=bootstrap.getText().toString().trim();persist();}
        catch(Exception e){status.setText("配置错误："+e.getMessage());return;}
        status.setText("正在检测主备上游并记录 IP / 延时…");
        final String secondary=secondaryHost.getText().toString().trim();
        final int secondPort=secondary.isEmpty()?31017:Integer.parseInt(secondaryPort.getText().toString().trim());
        new Thread(()->{
            UpstreamMonitor.Result primary=UpstreamMonitor.check(this,"主",name,upstreamPort,backup,false,null);
            UpstreamMonitor.Result second=secondary.isEmpty()?null:
                    UpstreamMonitor.check(this,"备用",secondary,secondPort,backup,false,null);
            String result="主 DNS："+(primary.success?"成功":"失败")+" · "+primary.latencyMs+" ms · "+primary.addressText;
            if(second!=null)result+="\n备用 DNS："+(second.success?"成功":"失败")+" · "+second.latencyMs+" ms · "+second.addressText;
            final String message=result;
            ui.post(()->{status.setText(message);refreshHistory();});
        },"DNS-test").start();
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
