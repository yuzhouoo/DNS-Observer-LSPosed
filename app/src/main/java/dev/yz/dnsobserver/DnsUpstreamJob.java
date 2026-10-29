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
    private final DnsJobRuns runs=new DnsJobRuns();
    private final android.os.Handler main=new android.os.Handler(android.os.Looper.getMainLooper());
    public static void schedule(Context ctx) {
        JobScheduler jobs=(JobScheduler)ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if(jobs==null) return;
        try {
            JobInfo existing=jobs.getPendingJob(ID);
            if(existing!=null && existing.isPeriodic() && existing.getIntervalMillis()==15*60*1000L &&
                existing.getNetworkType()==JobInfo.NETWORK_TYPE_ANY && existing.isPersisted())return;
        }catch(RuntimeException error){android.util.Log.w("DNSObserver","Cannot inspect existing job",error);}
        JobInfo info=new JobInfo.Builder(ID,new ComponentName(ctx,DnsUpstreamJob.class))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPeriodic(15*60*1000L)
                .setPersisted(true)
                .build();
        try {
            int result = jobs.schedule(info);
            if (result == JobScheduler.RESULT_FAILURE) {
                android.util.Log.w("DNSObserver", "Upstream health schedule was rejected");
            }
        } catch (SecurityException | IllegalArgumentException e) {
            // The settings screen must remain usable even when ROM rejects a job.
            android.util.Log.w("DNSObserver", "Upstream health scheduling unavailable", e);
        } catch (RuntimeException e) {
            android.util.Log.w("DNSObserver", "Upstream health scheduling failed", e);
        }
    }
    private boolean mayCheck(DnsJobRuns.Run run){
        SharedPreferences p=getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE);
        return !run.cancelled && !Thread.currentThread().isInterrupted() &&
            !p.getBoolean("takeover_enabled",false) && "idle".equals(DnsTakeoverService.uiPhase()) &&
            !DnsForwardService.isServing() && !DnsForwardService.isStarting() &&
            !DnsIpv6GlobalController.isRunning() && !DnsStateEpoch.busy();
    }
    @Override public boolean onStartJob(JobParameters params) {
        final DnsJobRuns.Run run=runs.begin();
        getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE).edit()
            .putString("upstream_job_status","正在检查是否满足检测条件").putLong("upstream_job_at",System.currentTimeMillis()).apply();
        Thread worker=new Thread(()->{
            String outcome="已完成";
            try {
                SharedPreferences p=getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE);
                if(!mayCheck(run)){outcome="跳过：接管会话中或任务已取消";return;}
                String bootstrap=p.getString("bootstrap","");
                String[] keys={"host","sub_host","secondary_host"};
                String[] ports={"port","sub_port","secondary_port"};
                for(int role=0;role<keys.length;role++){
                    if(!mayCheck(run)){outcome="已取消 / 接管已开启";break;}
                    String host=p.getString(keys[role],"");
                    if(!host.isEmpty())UpstreamMonitor.check(this,DnsFailover.NAMES[role],host,
                        safePort(p.getString(ports[role],"31017")),bootstrap,false,null,true);
                }
            }catch(Exception error){outcome="失败："+error.getClass().getSimpleName();}
            finally {
                final String completedOutcome=outcome;
                // Serialize completion with Android's onStopJob/onStartJob callbacks.
                main.post(()->{
                    if(runs.finish(run)){
                        getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE).edit()
                            .putString("upstream_job_status",completedOutcome).putLong("upstream_job_at",System.currentTimeMillis()).apply();
                        jobFinished(params,false);
                    }
                });
            }
        },"DNS-periodic-monitor");
        run.worker=worker;worker.start();return true;
    }
    @Override public boolean onStopJob(JobParameters params){
        runs.cancel();getSharedPreferences(DnsForwardService.PREFS,MODE_PRIVATE).edit()
            .putString("upstream_job_status","已被系统取消，等待下次周期调度").putLong("upstream_job_at",System.currentTimeMillis()).apply();
        return false;
    }
    @Override public void onDestroy(){runs.cancel();super.onDestroy();}
    private static int safePort(String value) {try {int p=Integer.parseInt(value);return p>0&&p<65536?p:31017;}catch(Exception e){return 31017;}}
}
