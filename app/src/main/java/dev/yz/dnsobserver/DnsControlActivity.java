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
    private EditText host, port, bootstrap;
    private CheckBox ipv6;
    private TextView status;
    private SharedPreferences prefs;
    private boolean visible;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        prefs = getSharedPreferences(DnsForwardService.PREFS, MODE_PRIVATE);
        build();
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
        root.addView(label("DNS 接管 · v0.3.0",23,FG));
        root.addView(label("保留现有 LSPosed DNS 监控；接管仅作用于常规 UDP/TCP 53。\n需要 Root。默认关闭、不随系统开机启动。",13,SECOND));
        status=label("正在检查状态…",15,FG);root.addView(status);
        host=field(root,"上游 DNS 域名（不带协议、端口）",prefs.getString("host",""));
        port=field(root,"上游 DNS 端口",prefs.getString("port","31017"));
        port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        bootstrap=field(root,"备用 Bootstrap DNS 纯 IP（可留空）",prefs.getString("bootstrap",""));
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
        button("紧急清理 Root 重定向规则",root).setOnClickListener(v->new Thread(()->{
            try {
                DnsRootRules.remove(this);
                ui.post(()->status.setText("已发送 Root 规则清理命令。若仍有服务运行请点关闭接管。"));
            } catch(Exception e) {
                ui.post(()->status.setText("Root 清理失败："+e.getMessage()));
            }
        },"DNS-emergency").start());
        root.addView(label("安全说明：本模块只清理 DOBSR53 专属防火墙链，不清空系统规则。单独的 Root 监视脚本会在应用进程消失时尝试回滚；无法保证所有 ROM / Root 实现上的绝对自动恢复。",12,SECOND));
    }
    private void persist() {
        prefs.edit().putString("host",host.getText().toString().trim())
                .putString("port",port.getText().toString().trim())
                .putString("bootstrap",bootstrap.getText().toString().trim())
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
            startForegroundService(i);
            status.setText("已提交启动任务，正在测试上游及安装专属规则…");
        } catch(Exception e){status.setText("配置错误："+e.getMessage());}
    }
    private void testServer() {
        final String name;
        final String backup;
        final int upstreamPort;
        try {name=checkedHost();upstreamPort=checkedPort();backup=bootstrap.getText().toString().trim();persist();}
        catch(Exception e){status.setText("配置错误："+e.getMessage());return;}
        status.setText("正在测试 Bootstrap 和上游 UDP/TCP DNS…");
        new Thread(()->{
            String result;
            try {
                InetAddress[] addrs=DnsBootstrap.resolve(name,backup);
                byte[] q=DnsPacket.probeQuestion();
                boolean udpOk=false,tcpOk=false;
                for(InetAddress addr:addrs) {
                    if(!udpOk) {
                        try(DatagramSocket sock=new DatagramSocket()) {
                            sock.connect(new InetSocketAddress(addr,upstreamPort));sock.setSoTimeout(2500);
                            sock.send(new DatagramPacket(q,q.length));
                            byte[] buffer=new byte[4096];DatagramPacket pkt=new DatagramPacket(buffer,buffer.length);sock.receive(pkt);
                            byte[] answer=java.util.Arrays.copyOf(buffer,pkt.getLength());udpOk=DnsPacket.validReply(q,answer);
                        } catch(Exception ignored) { }
                    }
                    if(!tcpOk) {
                        try(java.net.Socket sock=new java.net.Socket()) {
                            sock.connect(new InetSocketAddress(addr,upstreamPort),2500);sock.setSoTimeout(2500);
                            java.io.DataOutputStream out=new java.io.DataOutputStream(sock.getOutputStream());
                            out.writeShort(q.length);out.write(q);out.flush();
                            java.io.DataInputStream in=new java.io.DataInputStream(sock.getInputStream());
                            int len=in.readUnsignedShort();
                            if(len>=12&&len<=4096){byte[] answer=new byte[len];in.readFully(answer);tcpOk=DnsPacket.validReply(q,answer);}
                        } catch(Exception ignored) { }
                    }
                    if(udpOk&&tcpOk)break;
                }
                result="解析上游成功（"+addrs.length+" 个 IP） · UDP="+(udpOk?"成功":"失败")
                        +" · TCP="+(tcpOk?"成功":"失败")
                        +"\n启用需要 UDP 可用；TCP 失败会影响 TCP DNS 查询。";
            }catch(Exception e){result="检测失败："+e.getClass().getSimpleName()+": "+e.getMessage();}
            String finalResult=result;ui.post(()->status.setText(finalResult));
        },"DNS-test").start();
    }
    private final Runnable refresh=new Runnable(){@Override public void run(){
        if(!visible)return;
        // Do not overwrite active diagnostic messages while user is editing/testing.
        SharedPreferences p=getSharedPreferences(DnsForwardService.PREFS, MODE_PRIVATE);
        long at=p.getLong("updated",0);
        if(at>0 && System.currentTimeMillis()-at<20000) {
            status.setText((p.getBoolean("running",false)?"● 正在接管：":"○ 未接管：")+p.getString("status",""));
        }
        ui.postDelayed(this,3500);
    }};
    @Override protected void onResume(){super.onResume();visible=true;ui.removeCallbacks(refresh);ui.postDelayed(refresh,1200);}
    @Override protected void onPause(){visible=false;ui.removeCallbacks(refresh);super.onPause();}
}
