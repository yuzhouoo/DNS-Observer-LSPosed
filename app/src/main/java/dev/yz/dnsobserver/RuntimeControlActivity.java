package dev.yz.dnsobserver;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.os.Handler;
import android.widget.*;
import org.json.*;
import java.util.*;
import java.util.concurrent.*;

/** UI is a client of the independent Root manager, never its process owner. */
public final class RuntimeControlActivity extends Activity {
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private final Handler ui=new Handler();private boolean foreground,busy,loaded;
    private TextView state,detail,logs;private EditText bootstrap,core,profile,sim1,sim2,uids;
    private final EditText[] hosts=new EditText[3],ports=new EditText[3];
    private CheckBox ipv4,ipv6,boot,repair,block853,lan,dnsLog,sim;
    private Button dnsMode,proxyMode,offMode,save,refresh;
    private JSONObject config=new JSONObject(),latest=new JSONObject();private String diagnostic="",fullDiagnostic="",lastAction="";
    private LinearLayout root;
    @Override public void onCreate(Bundle b){super.onCreate(b);build();}
    private TextView text(String s,int size){TextView t=new TextView(this);t.setText(s);t.setTextColor(TechUi.TEXT);t.setTextSize(size);t.setPadding(0,12,0,10);root.addView(t);return t;}
    private EditText field(String hint){EditText e=new EditText(this);e.setHint(hint);TechUi.input(e);root.addView(e,new LinearLayout.LayoutParams(-1,-2));return e;}
    private CheckBox check(String label){CheckBox c=new CheckBox(this);c.setText(label);TechUi.toggle(c);root.addView(c);return c;}
    private Button button(String label,int tone,Runnable action){Button b=new Button(this);b.setText(label);TechUi.button(b,tone);root.addView(b,new LinearLayout.LayoutParams(-1,-2));b.setOnClickListener(v->action.run());return b;}
    private void build(){
        ScrollView screen=new ScrollView(this);screen.setBackground(TechUi.backdrop());root=new LinearLayout(this);root.setOrientation(1);int p=TechUi.dp(this,16);root.setPadding(p,p,p,p);screen.addView(root);setContentView(screen);TechUi.safeScreen(this,screen);
        text("域瞳 · 独立后台",26);text("v"+BuildConfig.VERSION_NAME+" · DNS53 / Mihomo TPROXY · 不依赖 APK 存活",12);
        state=text("正在读取模块真实状态…",19);detail=text("",13);state.setTextIsSelectable(true);detail.setTextIsSelectable(true);
        dnsMode=button("仅 DNS",TechUi.PRIMARY,()->apply("dns"));proxyMode=button("DNS + Mihomo TPROXY",TechUi.PRIMARY,()->apply("proxy"));offMode=button("全部停止并清理",TechUi.DANGER,()->apply("off"));
        text("运行选项 · 保存后由后台应用",19);
        ipv4=check("接管 IPv4（DNS / 代理）");ipv6=check("接管 IPv6（DNS / 代理）");boot=check("开机恢复所选模式（全部停止不自启）");repair=check("故障自动恢复（退避重试，可关闭）");lan=check("代理绕过局域网（DNS53 仍统一接管）");block853=check("限制外部 TCP/UDP 853 · 可能导致应用解析失败");dnsLog=check("记录接管 DNS 查询（本机日志轮转保存）");
        text("自建 DNS · 主 / 从 / 备",19);bootstrap=field("Bootstrap 纯 IP · 仅用于解析自建上游域名");for(int i=0;i<3;i++){hosts[i]=field(new String[]{"主 DNS 地址","从 DNS 地址（可选）","备 DNS 地址（可选）"}[i]);ports[i]=field("端口，例如 31053");ports[i].setInputType(2);}
        text("Mihomo · 仅 TPROXY",19);core=field("核心路径 /data/adb/yutong/mihomo/mihomo");profile=field("原始 YAML 路径 /data/adb/yutong/mihomo/config.yaml");
        button("导入已有 Mihomo 核心（不随模块打包）",TechUi.SECONDARY,()->pick(72));button("导入 Mihomo YAML 配置 / 订阅配置文件",TechUi.SECONDARY,()->pick(71));
        text("原始 YAML 和 provider 文件保留；运行副本统一接管端口、出站标记和 DNS。订阅 URL、代理组及节点继续由原配置管理。",12);
        button("查看代理组 / 选择节点",TechUi.SECONDARY,this::nodes);
        sim=check("按默认移动数据 SIM 切换 MATCH（Wi-Fi 时仍按数据 SIM）");sim1=field("SIM1 MATCH 目标，例如 DIRECT / 直连");sim2=field("SIM2 MATCH 目标，例如 代理");uids=field("代理绕过 UID，逗号分隔；DNS53 仍接管");
        save=button("保存并应用当前模式",TechUi.PRIMARY,()->apply(config.optString("mode","off")));
        refresh=button("刷新真实状态",TechUi.SECONDARY,this::read);
        button("旧版本接管清理（首次迁移使用）",TechUi.DANGER,()->{
            DnsTakeoverService.requestStop(this);Toast.makeText(this,"已请求旧接管清理，请等待完成后刷新",Toast.LENGTH_LONG).show();
        });
        button("旧版测速 / 历史与诊断",TechUi.SECONDARY,()->startActivity(new Intent(this,DnsControlActivity.class)));
        button("采集完整 Root 调试（规则 / 路由 / 上下文）",TechUi.SECONDARY,()->run(()->{String report=RootRuntimeBridge.call("diagnose").toString(2);ui.post(()->{fullDiagnostic=report;logs.setText(report);});return "完整诊断已采集，可复制下方摘要";}));
        button("复制调试摘要（可能包含 DNS 域名和本地路径）",TechUi.SECONDARY,()->{ClipboardManager cb=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);cb.setPrimaryClip(ClipData.newPlainText("域瞳调试",fullDiagnostic.isEmpty()?diagnostic:fullDiagnostic));});
        logs=text("调试日志：模块目录 /data/adb/yutong/logs；包含事件、Root 命令、DNS 和 Mihomo 日志。",12);logs.setTextIsSelectable(true);
    }
    private void pick(int code){Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(i,code);}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(result!=RESULT_OK||data==null||data.getData()==null)return;run(()->{try(java.io.InputStream in=getContentResolver().openInputStream(data.getData())){JSONObject r=RootRuntimeBridge.upload(req==72?"import-core":"import-config",in);ui.post(()->{if(req==72)core.setText(r.optString("path"));else profile.setText(r.optString("path"));});return r.toString(2);}});}
    private interface Task{String call()throws Exception;}
    private void run(Task task){if(busy)return;busy=true;lastAction="正在执行，请等待后台返回结果…";detail.setText(lastAction);paint();io.execute(()->{String message;try{message=task.call();}catch(Exception e){message=e.toString();}String value=message;ui.post(()->{busy=false;lastAction=value;detail.setText(value);paint();read();});});}
    private JSONObject values(String mode)throws Exception{
        JSONObject c=new JSONObject();c.put("mode",mode);c.put("ipv4",ipv4.isChecked());c.put("ipv6",ipv6.isChecked());c.put("boot",boot.isChecked());c.put("repair",repair.isChecked());c.put("block853",block853.isChecked());c.put("lan_bypass",lan.isChecked());c.put("dns_log",dnsLog.isChecked());c.put("bootstrap",bootstrap.getText().toString().trim());c.put("core",core.getText().toString().trim());c.put("profile",profile.getText().toString().trim());c.put("sim_match",sim.isChecked());c.put("sim1",sim1.getText().toString().trim());c.put("sim2",sim2.getText().toString().trim());JSONArray up=new JSONArray();for(int i=0;i<3;i++){String h=hosts[i].getText().toString().trim();if(!h.isEmpty())up.put(new JSONObject().put("host",h).put("port",Integer.parseInt(ports[i].getText().toString().trim())));}c.put("upstreams",up);JSONArray a=new JSONArray();for(String s:uids.getText().toString().split("[,，\\s]+"))if(!s.isEmpty())a.put(Integer.parseInt(s));c.put("bypass_uids",a);return c;
    }
    private void apply(String mode){if(!loaded){Toast.makeText(this,"模块状态尚未读取成功",Toast.LENGTH_LONG).show();return;}try{
        JSONObject c="off".equals(mode)?new JSONObject(config.toString()).put("mode","off"):values(mode);
        boolean first=!RootRuntimeBridge.selected(this);
        if(first)DnsTakeoverService.requestStop(this);
        getSharedPreferences(DnsForwardService.PREFS,0).edit().putBoolean("module_backend",true).putBoolean("takeover_enabled",false).commit();
        android.app.job.JobScheduler js=(android.app.job.JobScheduler)getSystemService(JOB_SCHEDULER_SERVICE);if(js!=null)js.cancel(DnsUpstreamJob.ID);
        run(()->{if(first){long end=System.currentTimeMillis()+65000;while(System.currentTimeMillis()<end){if("idle".equals(DnsTakeoverService.uiPhase())&&!DnsForwardService.isServing()&&!DnsForwardService.isStarting()&&!DnsIpv6GlobalController.isRunning())break;Thread.sleep(250);}if(!"idle".equals(DnsTakeoverService.uiPhase()))throw new IllegalStateException("旧接管清理仍在进行，请稍后刷新重试");}return RootRuntimeBridge.call("apply",RootRuntimeBridge.encode(c.toString())).toString(2);});
    }catch(Exception e){detail.setText("配置错误："+e.getMessage());}}
    private void fill(JSONObject c){
        ipv4.setChecked(c.optBoolean("ipv4",true));ipv6.setChecked(c.optBoolean("ipv6",true));boot.setChecked(c.optBoolean("boot"));repair.setChecked(c.optBoolean("repair",true));lan.setChecked(c.optBoolean("lan_bypass",true));block853.setChecked(c.optBoolean("block853"));dnsLog.setChecked(c.optBoolean("dns_log",true));bootstrap.setText(c.optString("bootstrap"));core.setText(c.optString("core","/data/adb/yutong/mihomo/mihomo"));profile.setText(c.optString("profile","/data/adb/yutong/mihomo/config.yaml"));sim.setChecked(c.optBoolean("sim_match"));sim1.setText(c.optString("sim1","DIRECT"));sim2.setText(c.optString("sim2","代理"));JSONArray a=c.optJSONArray("upstreams");for(int i=0;i<3;i++){JSONObject u=a==null?null:a.optJSONObject(i);hosts[i].setText(u==null?"":u.optString("host"));ports[i].setText(u==null?"31053":String.valueOf(u.optInt("port",31053)));}a=c.optJSONArray("bypass_uids");StringBuilder ids=new StringBuilder();if(a!=null)for(int i=0;i<a.length();i++){if(i>0)ids.append(',');ids.append(a.optInt(i));}uids.setText(ids.toString());
        // Migrate DNS form defaults only on a fresh module, without starting anything.
        if(c.optJSONArray("upstreams")==null){android.content.SharedPreferences p=getSharedPreferences(DnsForwardService.PREFS,0);bootstrap.setText(p.getString("bootstrap",""));String[] hs={"host","sub_host","secondary_host"},ps={"port","sub_port","secondary_port"};for(int i=0;i<3;i++){hosts[i].setText(p.getString(hs[i],""));ports[i].setText(p.getString(ps[i],"31053"));}}
    }
    private void paint(){for(Button b:new Button[]{dnsMode,proxyMode,offMode,save,refresh})b.setEnabled(!busy);String mode=config.optString("mode","off");dnsMode.setSelected("dns".equals(mode));proxyMode.setSelected("proxy".equals(mode));offMode.setSelected("off".equals(mode));}
    private void read(){if(busy)return;busy=true;io.execute(()->{JSONObject r=null;String failure="";try{r=RootRuntimeBridge.call("status");RootRuntimeRecords.importRows(this,r.optJSONArray("dns"));}catch(Exception e){failure=e.toString();}JSONObject value=r;String error=failure;ui.post(()->{busy=false;if(value==null){state.setText("模块未连接 / Root 未确认");detail.setText(error);loaded=false;}else{latest=value;JSONObject c=value.optJSONObject("config");if(c!=null){config=c;if(!loaded)fill(c);}loaded=true;JSONObject s=value.optJSONObject("status");if(s!=null){state.setText("目标模式："+modeName(s.optString("mode"))+"\n后台状态："+phaseName(s.optString("phase")));detail.setText("DNS："+statusName(s.optString("dns"))+"  Mihomo："+statusName(s.optString("proxy"))+"\nIPv4："+statusName(s.optString("ipv4"))+"  IPv6："+statusName(s.optString("ipv6"))+"\n后台 PID："+s.optInt("pid")+"  最近更新："+new java.util.Date(s.optLong("updated"))+"\nSIM MATCH："+s.optString("sim")+"\n"+s.optString("error")+"\n最近操作："+lastAction);state.setTextColor(s.optString("phase").startsWith("running")?TechUi.GREEN:"off".equals(s.optString("phase"))?TechUi.MUTED:TechUi.AMBER);}try{diagnostic=value.toString(2);}catch(Exception ignored){}}paint();});});}
    private String statusName(String s){switch(s){case "off":return "已停止";case "verified":return "校验通过";case "listening":return "监听已就绪";case "ready":return "API / 监听已就绪";case "failed":return "异常";case "exited":return "进程已退出";case "unavailable":return "暂不可用";case "upstream_unavailable":return "上游不可达";case "listener_pending":return "等待监听恢复";default:return s;}}
    private String modeName(String m){return "dns".equals(m)?"仅 DNS":"proxy".equals(m)?"DNS + TPROXY":"全部停止";}
    private String phaseName(String p){switch(p){case "running":return "运行中 · 已校验";case "running_rolled_back":return "已恢复上一可用配置";case "off":case "not_running":return "已停止";case "starting":return "启动校验中";case "stopping":return "停止清理中";case "repairing_rules":return "规则修复中";case "failed":return "失败 · 查看原因 / 退避重试";case "proxy_unavailable_dns_running":return "代理异常 · DNS 独立运行";case "partial":return "部分协议不可用 · 正常协议保留";case "upstream_unavailable":return "自建 DNS 上游不可用 · 规则仍保留";case "degraded":return "状态异常 · 自动修复关闭";default:return p;}}
    private void nodes(){run(()->{JSONObject r=RootRuntimeBridge.call("proxies");ui.post(()->chooseGroup(r));return "代理组信息已读取";});}
    private void chooseGroup(JSONObject r){JSONObject p=r.optJSONObject("proxies");if(p==null)return;ArrayList<String> groups=new ArrayList<>();Iterator<String> it=p.keys();while(it.hasNext()){String k=it.next();JSONObject g=p.optJSONObject(k);if(g!=null&&g.optJSONArray("all")!=null&&"Selector".equalsIgnoreCase(g.optString("type")))groups.add(k);}new AlertDialog.Builder(this).setTitle("选择代理组").setItems(groups.toArray(new String[0]),(d,n)->{JSONObject g=p.optJSONObject(groups.get(n));JSONArray a=g.optJSONArray("all");String[] names=new String[a.length()];for(int i=0;i<names.length;i++)names[i]=a.optString(i);new AlertDialog.Builder(this).setTitle("当前："+g.optString("now")).setItems(names,(dialog,j)->run(()->RootRuntimeBridge.call("select",RootRuntimeBridge.encode(groups.get(n)),RootRuntimeBridge.encode(names[j])).toString())).show();}).show();}
    private final Runnable tick=new Runnable(){public void run(){if(foreground){read();ui.postDelayed(this,5000);}}};
    @Override protected void onResume(){super.onResume();foreground=true;ui.post(tick);}
    @Override protected void onPause(){foreground=false;ui.removeCallbacks(tick);super.onPause();}
    @Override protected void onDestroy(){io.shutdown();super.onDestroy();}
}
