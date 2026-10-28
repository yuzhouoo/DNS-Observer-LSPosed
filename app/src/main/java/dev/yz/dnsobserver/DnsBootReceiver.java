package dev.yz.dnsobserver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

/** Boot startup is opt-in and requires an explicit previously enabled takeover. */
public final class DnsBootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context ctx,Intent intent){
        if(intent==null||!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()))return;
        SharedPreferences p=ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE);
        if(!p.getBoolean("takeover_boot",false)||!p.getBoolean("takeover_enabled",false))return;
        try{DnsTakeoverService.requestStart(ctx);}
        catch(Exception error){DnsTakeoverService.event(ctx,"BOOT_START_FAILED: "+error.getClass().getSimpleName()+" "+error.getMessage());}
    }
}
