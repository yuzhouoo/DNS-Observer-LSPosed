package dev.yz.dnsobserver;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;

/** Best-effort 15-minute health checks when DNS redirect is OFF. No Root. */
public final class DnsUpstreamJob extends JobService {
    private static final int ID=0x444e53;
    private volatile boolean cancelled;
    public static void schedule(Context ctx) {
        JobScheduler jobs=(JobScheduler)ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if(jobs==null) return;
        JobInfo info=new JobInfo.Builder(ID,new ComponentName(ctx,DnsUpstreamJob.class))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPeriodic(15*60*1000L)
                .build();
        jobs.schedule(info);
    }
    @Override public boolean onStartJob(JobParameters params) {
        cancelled=false;
        new Thread(()->{
            try {
                SharedPreferences p=getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE);
                // Avoid racing the Root redirect; the active foreground service monitors itself.
                if(!cancelled && !p.getBoolean("running",false)) {
                    String primary=p.getString("host","");
                    int port=safePort(p.getString("port","31017"));
                    String bootstrap=p.getString("bootstrap","");
                    if(!primary.isEmpty()) UpstreamMonitor.check(this,"主",primary,port,bootstrap,false,null);
                    String secondary=p.getString("secondary_host","");
                    if(!cancelled && !secondary.isEmpty()) UpstreamMonitor.check(this,"备用",secondary,
                            safePort(p.getString("secondary_port","31017")),bootstrap,false,null);
                }
            } finally { jobFinished(params,false); }
        },"DNS-periodic-monitor").start();
        return true;
    }
    @Override public boolean onStopJob(JobParameters params) {cancelled=true;return false;}
    private static int safePort(String value) {try {int p=Integer.parseInt(value);return p>0&&p<65536?p:31017;}catch(Exception e){return 31017;}}
}
