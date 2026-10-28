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
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
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
    private static final int BACKGROUND = Color.rgb(11, 18, 32);
    private static final int PANEL = Color.rgb(22, 32, 51);
    private static final int TEXT = Color.rgb(239, 246, 255);
    private static final int MUTED = Color.rgb(151, 173, 195);
    private static final int AQUA = Color.rgb(91, 218, 209);
    private static final int GREEN = Color.rgb(116, 223, 174);
    private static final int RED = Color.rgb(255, 133, 139);
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
    private Spinner statusSpinner;
    private boolean active;
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
        main.setBackgroundColor(BACKGROUND);
        setContentView(main);

        TextView title = text("DNS Observer", 27, TEXT, true);
        main.addView(title);
        TextView subtitle = text("系统 DNS 观察 · LSPosed API 102 · v0.5.5", 12, MUTED, false);
        subtitle.setPadding(0, dp(2), 0, dp(12));
        main.addView(subtitle);

        LinearLayout overview = panel();
        state = text("检查 Hook 状态…", 14, AQUA, true);
        overview.addView(state);
        stats = text("记录 0 · 域名 0 · 失败 0", 15, TEXT, true);
        stats.setPadding(0, dp(10), 0, dp(5));
        overview.addView(stats);
        note = text("", 12, MUTED, false);
        overview.addView(note);
        main.addView(overview);

        Button dnsControl = new Button(this);
        dnsControl.setText("DNS 接管 · 主备 DNS · IP 历史");
        dnsControl.setTextSize(13);
        dnsControl.setAllCaps(false);
        dnsControl.setOnClickListener(v -> startActivity(
                new Intent(this, DnsControlActivity.class)));
        main.addView(dnsControl, new LinearLayout.LayoutParams(-1, dp(44)));

        LinearLayout controls = new LinearLayout(this);
        controls.setGravity(Gravity.CENTER_VERTICAL);
        controls.setPadding(0, dp(10), 0, dp(6));
        Switch running = new Switch(this);
        running.setText("记录 DNS");
        running.setTextColor(TEXT);
        running.setTextSize(14);
        running.setChecked(prefs.getBoolean("enabled", true));
        running.setOnCheckedChangeListener((b, checked) -> {
            prefs.edit().putBoolean("enabled", checked).apply();
            toast(checked ? "已恢复记录" : "已暂停记录（Hook 仍保留）");
            requestRefresh();
        });
        controls.addView(running, new LinearLayout.LayoutParams(0, dp(42), 1));
        Button export = action("导出 CSV");
        export.setOnClickListener(v -> exportFile());
        controls.addView(export);
        Button clear = action("清空");
        clear.setOnClickListener(v -> confirmClear());
        controls.addView(clear);
        main.addView(controls);

        LinearLayout filters = new LinearLayout(this);
        filters.setGravity(Gravity.CENTER_VERTICAL);
        search = new EditText(this);
        search.setSingleLine(true);
        search.setTextSize(13);
        search.setTextColor(TEXT);
        search.setHintTextColor(MUTED);
        search.setHint("域名 / 应用 / 包名 / IP / DNS 服务器");
        search.setPadding(dp(12), dp(5), dp(7), dp(5));
        search.setBackground(bg(PANEL, dp(11)));
        filters.addView(search, new LinearLayout.LayoutParams(0, dp(42), 1));
        statusSpinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, new String[]{"全部", "成功", "失败"});
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        statusSpinner.setAdapter(adapter);
        statusSpinner.setBackground(bg(PANEL, dp(9)));
        filters.addView(statusSpinner, new LinearLayout.LayoutParams(dp(78), dp(42)));
        main.addView(filters);

        TextView caption = text("解析记录 · 3 秒刷新 · 状态筛选 · 点击展开 IP", 12, MUTED, false);
        caption.setPadding(0, dp(11), 0, dp(8));
        main.addView(caption);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        results = new LinearLayout(this);
        results.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(results);
        main.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                ui.removeCallbacks(debounced);
                ui.postDelayed(debounced, 360);
            }
            @Override public void afterTextChanged(Editable e) { }
        });
        statusSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View view, int pos, long id) {
                filter = pos;
                requestRefresh();
            }
            @Override public void onNothingSelected(AdapterView<?> p) { }
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
        b.setPadding(dp(5), 0, dp(5), 0);
        b.setBackground(bg(PANEL, dp(9)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(78), dp(39));
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
        d.setCornerRadius(r);
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
            result.setPadding(dp(8),0,0,0);
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
    private void confirmClear() {
        new AlertDialog.Builder(this)
                .setTitle("清空全部解析记录？")
                .setMessage("此操作不可撤销，导出前请确认。")
                .setNegativeButton("取消", null)
                .setPositiveButton("清空", (dialog, which) -> io.execute(() -> {
                    try {
                        database.clearAll();
                        ui.post(() -> { toast("记录已清空"); requestRefresh(); });
                    } catch (Throwable t) { ui.post(() -> toast("清空失败")); }
                })).show();
    }

    private void exportFile() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/csv");
        intent.putExtra(Intent.EXTRA_TITLE,
                "dns-observer-" + new SimpleDateFormat("yyyyMMdd-HHmm", Locale.US)
                        .format(new Date()) + ".csv");
        startActivityForResult(intent, REQ_EXPORT);
    }
    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_EXPORT || resultCode != RESULT_OK || data == null) return;
        Uri selected = data.getData();
        if (selected == null) return;
        io.execute(() -> {
            try (OutputStream output = getContentResolver().openOutputStream(selected, "w")) {
                if (output == null) throw new IllegalStateException("file stream unavailable");
                database.exportAll(output);
                ui.post(() -> toast("CSV 导出完成"));
            } catch (Throwable t) { ui.post(() -> toast("CSV 导出失败: " + t.getClass().getSimpleName())); }
        });
    }
    @Override protected void onDestroy() {
        io.shutdown();
        super.onDestroy();
    }
}
