package dev.yz.dnsobserver;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public final class MainActivity extends Activity {
    private static final int BACKGROUND=TechUi.BG,PANEL=TechUi.PANEL,TEXT=TechUi.TEXT,
        MUTED=TechUi.MUTED,AQUA=TechUi.CYAN,GREEN=TechUi.GREEN,RED=TechUi.RED;
    private static final int REQ_EXPORT = 41;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final AtomicInteger requests = new AtomicInteger(0);
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.getDefault());
    private DnsDb database;
    private SharedPreferences prefs;
    private TextView state, stats, note;
    private LinearLayout results;
    private EditText search;
    private final Button[] filterButtons=new Button[3];
    private Switch recordingSwitch;
    private Button dnsControl,exportButton,clearButton;
    private boolean active,clearDialogOpen;
    private static volatile boolean exportBusy,clearBusy;
    private int filter;

    @Override protected void onCreate(Bundle stateBundle) {
        super.onCreate(stateBundle);
        getWindow().setStatusBarColor(BACKGROUND);
        getWindow().setNavigationBarColor(BACKGROUND);
        database = new DnsDb(this);
        prefs = getSharedPreferences(SecureProvider.PREFS, 0);
        buildUi();
        // Best-effort old-record label upgrade. Work off the main thread.
        io.execute(() -> {
            try { database.backfillAppNames(getApplicationContext()); }
            catch (Throwable ex) { android.util.Log.w("DNSObserver", "Label backfill skipped", ex); }
        });
    }

    private void buildUi() {
        LinearLayout main = new LinearLayout(this);
        main.setOrientation(LinearLayout.VERTICAL);
        main.setPadding(dp(16), dp(18), dp(16), dp(8));
        ScrollView screen=new ScrollView(this);screen.setFillViewport(true);screen.setClipToPadding(true);
        screen.setBackground(TechUi.backdrop());screen.addView(main,new ScrollView.LayoutParams(-1,-2));
        setContentView(screen);TechUi.safeScreen(this,screen);

        TextView title = text(getString(R.string.app_name), 28, TEXT, true);
        title.setLetterSpacing(0.035f);
        main.addView(title);
        TextView subtitle = text("系统 DNS 观察 · LSPosed API 102 · v"+BuildConfig.VERSION_NAME, 12, MUTED, false);
        subtitle.setPadding(0, dp(2), 0, dp(12));
        main.addView(subtitle);

        LinearLayout overview = panel();
        state = text("检查 Hook 状态…", 14, AQUA, true);
        overview.addView(state);
        state.setLetterSpacing(0.02f);
        stats = text("记录 0 · 域名 0 · 失败 0", 15, TEXT, true);
        stats.setPadding(0, dp(10), 0, dp(5));
        overview.addView(stats);
        note = text("", 12, MUTED, false);
        overview.addView(note);
        main.addView(overview);TechUi.spaced(overview);

        dnsControl = new Button(this);
        dnsControl.setText("DNS 接管 · 主备 DNS · IP 历史");
        dnsControl.setTextSize(13);
        dnsControl.setAllCaps(false);
        dnsControl.setOnClickListener(v -> startActivity(
                new Intent(this, DnsControlActivity.class)));
        TechUi.button(dnsControl,TechUi.PRIMARY);
        LinearLayout.LayoutParams launchLp=new LinearLayout.LayoutParams(-1,-2);launchLp.topMargin=dp(12);launchLp.bottomMargin=dp(12);
        main.addView(dnsControl,launchLp);

        LinearLayout controls = new LinearLayout(this);
        controls.setGravity(Gravity.CENTER_VERTICAL);
        controls.setPadding(0, dp(10), 0, dp(6));
        Switch running = recordingSwitch = new Switch(this);
        running.setText(prefs.getBoolean("enabled",true)?"DNS 记录 · 已开启":"DNS 记录 · 已暂停");
        running.setTextColor(TEXT);
        running.setTextSize(14);
        running.setChecked(prefs.getBoolean("enabled", true));
        running.setOnCheckedChangeListener((b, checked) -> {
            prefs.edit().putBoolean("enabled", checked).apply();
            running.setText(checked?"DNS 记录 · 已开启":"DNS 记录 · 已暂停");
            toast(checked ? "已恢复记录；系统端连接状态见上方" : "已暂停记录（Hook 仍保留）");
            requestRefresh();
        });
        TechUi.toggle(running);main.addView(running,new LinearLayout.LayoutParams(-1,-2));
        TechUi.spaced(running);
        Button export = exportButton = action("导出 CSV");
        export.setOnClickListener(v -> exportFile());
        controls.addView(export,new LinearLayout.LayoutParams(0,-2,1));
        Button clear = clearButton = action("清空记录");
        clear.setOnClickListener(v -> confirmClear());
        LinearLayout.LayoutParams clearLp=new LinearLayout.LayoutParams(0,-2,1);clearLp.leftMargin=dp(10);
        controls.addView(clear,clearLp);TechUi.button(clear,TechUi.DANGER);exportButton.setEnabled(false);clearButton.setEnabled(false);
        main.addView(controls);

        TextView filterTitle=text("记录筛选",14,TEXT,true);filterTitle.setPadding(0,dp(12),0,dp(10));main.addView(filterTitle);
        search = new EditText(this);
        search.setSingleLine(true);search.setHint("搜索域名、应用、IP 或 DNS 服务器");
        TechUi.input(search);main.addView(search,new LinearLayout.LayoutParams(-1,-2));
        LinearLayout filters=new LinearLayout(this);filters.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams filtersLp=new LinearLayout.LayoutParams(-1,-2);filtersLp.topMargin=dp(10);
        main.addView(filters,filtersLp);
        String[] options={"全部","成功","失败"};
        for(int index=0;index<options.length;index++){
            final int choice=index;Button chip=new Button(this);chip.setText(options[index]);TechUi.button(chip,TechUi.SECONDARY);
            filterButtons[index]=chip;chip.setSelected(index==filter);chip.setText(options[index]+(index==filter?" ✓":""));
            chip.setContentDescription("结果筛选："+options[index]+(index==filter?"，已选中":""));
            LinearLayout.LayoutParams chipLp=new LinearLayout.LayoutParams(0,-2,1);if(index>0)chipLp.leftMargin=dp(8);
            filters.addView(chip,chipLp);
            chip.setOnClickListener(v->{filter=choice;
                for(int i=0;i<filterButtons.length;i++){filterButtons[i].setSelected(i==filter);filterButtons[i].setText(options[i]+(i==filter?" ✓":""));filterButtons[i].setContentDescription("结果筛选："+options[i]+(i==filter?"，已选中":""));}
                requestRefresh();});
        }

        TextView caption = text("解析记录 · 3 秒刷新 · 状态筛选 · 点击展开 IP", 12, MUTED, false);
        caption.setPadding(0, dp(11), 0, dp(8));
        main.addView(caption);
        results = new LinearLayout(this);
        results.setOrientation(LinearLayout.VERTICAL);
        // One page scroller keeps controls reachable on small screens / large fonts.
        main.addView(results,new LinearLayout.LayoutParams(-1,-2));

        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                ui.removeCallbacks(debounced);
                ui.postDelayed(debounced, 360);
            }
            @Override public void afterTextChanged(Editable e) { }
        });

    }

    private LinearLayout panel() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setBackground(bg(PANEL, dp(16)));
        l.setPadding(dp(15), dp(13), dp(15), dp(13));
        return l;
    }
    private Button action(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextSize(11);
        b.setTextColor(TEXT);
        b.setAllCaps(false);
        b.setMinWidth(0);
        b.setMinimumWidth(0);
        b.setPadding(dp(5), dp(7), dp(5), dp(7));b.setMinHeight(dp(46));
        TechUi.button(b,TechUi.SECONDARY);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(78), -2);
        lp.leftMargin = dp(5);
        b.setLayoutParams(lp);
        return b;
    }
    private TextView text(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return t;
    }
    private GradientDrawable bg(int color, int r) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(r);d.setStroke(dp(1),0xff29415c);
        return d;
    }
    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private void toast(String value) { Toast.makeText(this, value, Toast.LENGTH_SHORT).show(); }

    private final Runnable debounced = this::requestRefresh;
    private final Runnable polling = new Runnable() {
        @Override public void run() {
            if (!active) return;
            requestRefresh();
            ui.postDelayed(this, 3000);
        }
    };
    @Override protected void onResume() {
        super.onResume();
        active = true;
        ui.removeCallbacks(polling);
        polling.run();
    }
    @Override protected void onPause() {
        active = false;
        ui.removeCallbacks(polling);
        ui.removeCallbacks(debounced);
        super.onPause();
    }
    private void requestRefresh() {
        if (!active) return;
        final String query = search.getText().toString();
        final int f = filter;
        final int index = requests.incrementAndGet();
        io.execute(() -> {
            try {
                DnsDb.Stats summary = database.stats();
                List<DnsDb.Entry> items = database.latest(query, f);
                boolean localProviderOk;
                try {
                    Bundle probe = getContentResolver().call(
                            Uri.parse("content://" + SecureProvider.AUTHORITY),
                            "selfTest", null, null);
                    localProviderOk = probe != null && probe.getBoolean("ok", false);
                } catch (Throwable ignored) {
                    localProviderOk = false;
                }
                final boolean providerReady = localProviderOk;
                ui.post(() -> {
                    if (!active || index != requests.get()) return;
                    stats.setText("记录 " + summary.total + "  ·  域名 " + summary.domains +
                            "  ·  失败 " + summary.failures);
                    long hb = prefs.getLong("heartbeat", 0L);
                    boolean live = hb > 0 && System.currentTimeMillis() - hb < 25000L;
                    boolean recording=prefs.getBoolean("enabled",true);
                    recordingSwitch.setText(!recording?"DNS 记录 · 已暂停":live?"DNS 记录 · 记录中":"DNS 记录 · 等待系统端");
                    String takeoverPhase=DnsTakeoverService.uiPhase();
                    String takeoverSummary="starting".equals(takeoverPhase)?"正在开启":
                        "stopping".equals(takeoverPhase)?"正在关闭":
                        DnsForwardService.isServing()||DnsIpv6GlobalController.isServing()?"代理运行中 · 查看校验状态":
                        getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE).getBoolean("takeover_enabled",false)?"已请求 · 状态待确认":"未请求 · 查看实时状态";
                    dnsControl.setText("DNS 接管 · "+takeoverSummary);
                    setDataButtons(summary.total);
                    state.setText(live ? "● 系统端心跳正常"
                            : providerReady ? "○ 系统端无心跳（App 存储通道正常）"
                            : "○ 系统端无心跳（App 存储通道异常）");
                    state.setTextColor(live ? GREEN : RED);
                    long dropped = prefs.getLong("lost", 0L);
                    String err = prefs.getString("lastError", "");
                    note.setText("保存最近 14 天 / 最多 20,000 条" +
                            (dropped > 0 ? "  ·  队列丢失 " + dropped : "") +
                            (!err.isEmpty() ? "  ·  IPC: " + err : "") +
                            (prefs.getBoolean("enabled", true) ? "" : "  ·  已暂停") +
                            (live ? "" : "  ·  检查 LSPosed 日志 DNSObserver:"));
                    render(items);
                });
            } catch (Throwable t) {
                ui.post(() -> {
                    if (active && index == requests.get()) {
                        note.setText("查询失败: " + t.getClass().getSimpleName());
                    }
                });
            }
        });
    }

    private void render(List<DnsDb.Entry> items) {
        results.removeAllViews();
        if (items.isEmpty()) {
            TextView empty = text("暂无匹配的 DNS 记录。请确认 LSPosed 系统框架作用域、重启设备并访问一个新域名。",
                    13, MUTED, false);
            empty.setPadding(dp(12), dp(18), dp(12), dp(18));
            results.addView(empty);
            return;
        }
        for (DnsDb.Entry e : items) {
            LinearLayout card = panel();
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.bottomMargin = dp(7);
            card.setLayoutParams(lp);
            LinearLayout heading=new LinearLayout(this);
            heading.setOrientation(LinearLayout.HORIZONTAL);
            heading.setGravity(Gravity.CENTER_VERTICAL);
            TextView host=text(e.host,15,TEXT,true);
            host.setMaxLines(2);
            heading.addView(host,new LinearLayout.LayoutParams(0,-2,1));
            TextView result=text(e.rc==0?"成功":"失败",12,e.rc==0?GREEN:RED,true);
            TechUi.badge(result,e.rc==0);
            heading.addView(result);
            card.addView(heading);
            // Old v0.4.0 rows have no appName; never discard their known package.
            String appLabel=e.appName;
            if(appLabel==null || appLabel.isEmpty() || "未知应用".equals(appLabel)) {
                String knownPkg=e.packages==null?"":e.packages.trim();
                appLabel=knownPkg.isEmpty()?("UID "+e.uid):knownPkg.split(",",2)[0].trim();
            }
            TextView app=text(appLabel+" · "+e.packages,12,MUTED,false);
            app.setPadding(0,dp(6),0,dp(3));card.addView(app);
            String addresses=e.ips==null?"":e.ips;
            String[] addressList=addresses.isEmpty()?new String[0]:addresses.split(", ");
            boolean many=addressList.length>2;
            String preview=many?addressList[0]+", "+addressList[1]
                    +"  ·  另有 "+(addressList.length-2)+" 个，点击展开":addresses;
            TextView ip=text(addresses.isEmpty()?"未返回 IP":preview,13,AQUA,false);
            ip.setPadding(0,dp(5),0,dp(5));
            card.addView(ip);
            if(many)TechUi.disclosure(ip);
            if(many) ip.setOnClickListener(new View.OnClickListener(){boolean expanded;
                @Override public void onClick(View v){expanded=!expanded;ip.setText(expanded?addresses:preview);}
            });
            String dnsKind=(e.dnsType==null||e.dnsType.isEmpty()||"未知".equals(e.dnsType))
                    ?"系统解析事件（未观测到传输协议）":e.dnsType;
            String server=(e.dnsServer==null||e.dnsServer.isEmpty()||"未知".equals(e.dnsServer))
                    ?"历史事件无服务器快照":e.dnsServer;
            TextView dns=text("DNS 类型："+dnsKind+"\nDNS 服务器："+server,
                    12,MUTED,false);
            dns.setPadding(0,dp(5),0,dp(4));card.addView(dns);
            TextView source=text(safe(e.dnsSource),11,MUTED,false);card.addView(source);
            String stamp;
            synchronized (timeFormat) { stamp = timeFormat.format(new Date(e.ts)); }
            String metaText=stamp+"  ·  " +(e.rc==0?"成功":"错误 "+e.rc)+" · "
                    +e.latency+" ms · UID "+e.uid+" · NetID "+e.net;
            TextView meta=text(metaText,11,MUTED,false);
            meta.setPadding(0,dp(7),0,0);card.addView(meta);
            card.setOnLongClickListener(v -> {
                String value = e.host + (e.ips == null || e.ips.isEmpty() ? "" : "\n" + e.ips);
                ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("DNS lookup", value));
                toast("已复制域名和解析结果");
                return true;
            });
            results.addView(card);
        }
    }

    private static String safe(String s) {return s==null||s.isEmpty()?"未知":s;}
    private void setDataButtons(long count) {
        exportButton.setEnabled(!exportBusy&&!clearBusy&&count>0);
        clearButton.setEnabled(!exportBusy&&!clearBusy&&count>0);
        exportButton.setText(exportBusy?"正在导出…":count==0?"暂无记录":"导出 CSV");
        clearButton.setText(clearBusy?"正在清空…":count==0?"记录为空":"清空记录");
        exportButton.setAlpha(1f);
        clearButton.setAlpha(1f);
    }
    private void confirmClear() {
        if(clearBusy||exportBusy||clearDialogOpen)return;
        clearDialogOpen=true;
        AlertDialog confirmation=new AlertDialog.Builder(this)
                .setTitle("清空全部解析记录？")
                .setMessage("此操作不可撤销，导出前请确认。")
                .setNegativeButton("取消", null)
                .setPositiveButton("清空", (dialog, which) -> {
                    if(clearBusy||exportBusy)return;
                    clearBusy=true;setDataButtons(1);
                    io.execute(() -> {
                    try {
                        database.clearAll();
                        ui.post(() -> {clearBusy=false;setDataButtons(0);toast("记录已清空"); requestRefresh(); });
                    } catch (Throwable t) { ui.post(() -> {clearBusy=false;setDataButtons(1);toast("清空失败");requestRefresh();}); }
                });}).create();
        confirmation.setOnDismissListener(d->clearDialogOpen=false);confirmation.show();
    }

    private void exportFile() {
        if(exportBusy||clearBusy)return;
        exportBusy=true;setDataButtons(1);
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/csv");
        intent.putExtra(Intent.EXTRA_TITLE,
                "dns-observer-" + new SimpleDateFormat("yyyyMMdd-HHmm", Locale.US)
                        .format(new Date()) + ".csv");
        try{startActivityForResult(intent, REQ_EXPORT);}
        catch(Exception error){exportBusy=false;setDataButtons(1);toast("无法打开保存位置");}
    }
    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_EXPORT)return;
        if(resultCode != RESULT_OK || data == null){exportBusy=false;setDataButtons(1);requestRefresh();return;}
        Uri selected = data.getData();
        if (selected == null){exportBusy=false;setDataButtons(1);requestRefresh();return;}
        io.execute(() -> {
            try (OutputStream output = getContentResolver().openOutputStream(selected, "w")) {
                if (output == null) throw new IllegalStateException("file stream unavailable");
                database.exportAll(output);
                ui.post(() -> {exportBusy=false;setDataButtons(1);toast("CSV 导出完成");requestRefresh();});
            } catch (Throwable t) { ui.post(() -> {exportBusy=false;setDataButtons(1);toast("CSV 导出失败: " + t.getClass().getSimpleName());requestRefresh();}); }
        });
    }
    @Override protected void onDestroy() {
        io.shutdown();
        super.onDestroy();
    }
}
