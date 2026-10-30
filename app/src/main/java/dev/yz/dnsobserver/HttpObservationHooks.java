package dev.yz.dnsobserver;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.net.Uri;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.HttpURLConnection;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import io.github.libxposed.api.XposedInterface;

/** Opt-in scoped Java HTTP API observation. Never consume a stream or change a request. */
public final class HttpObservationHooks {
    private static Context context;
    private static Handler worker;
    private static final ArrayDeque<Bundle> queue=new ArrayDeque<>();
    private static final HashSet<Method> hooked=new HashSet<>();
    private static final ThreadLocal<Boolean> inside=ThreadLocal.withInitial(()->false);
    private static volatile long configAt;private static volatile boolean enabled;
    public static synchronized void attach(Context c){
        context=c.getApplicationContext()==null?c:c.getApplicationContext();
        if(worker==null){HandlerThread t=new HandlerThread("DNS-http-observer");t.start();worker=new Handler(t.getLooper());worker.postDelayed(HttpObservationHooks::flush,android.os.Process.myUid()==1000?12000:1500);}
    }
    private static void submit(DnsObservation.Http h,String result){
        if(h==null)return;
        Bundle b=new Bundle();b.putString("url",h.url);b.putString("method",h.method);
        b.putString("mime",h.evidence.equals("HTTP_API_MEDIA_TYPE")?"application/dns-message":"");
        b.putString("apiResult",result);b.putBoolean("dnsParam",h.dnsParam);b.putString("dnsQuery",h.dnsQuery);b.putString("queryHint",h.detail);
        synchronized(queue){if(queue.size()>=200)queue.removeFirst();queue.addLast(b);}
    }
    private static void flush(){
        Context c=context;
        try{
            if(c!=null){
                long now=android.os.SystemClock.elapsedRealtime();
                if(now-configAt>5000 || configAt==0){Bundle config=c.getContentResolver().call(Uri.parse("content://"+SecureProvider.AUTHORITY),"httpConfig",null,null);enabled=config!=null&&config.getBoolean("enabled",false);configAt=now;}
                ArrayList<Bundle> batch=new ArrayList<>();synchronized(queue){for(int n=0;n<20&&!queue.isEmpty();n++)batch.add(queue.removeFirst());}
                if(enabled&&!batch.isEmpty()){Bundle data=new Bundle();data.putParcelableArrayList("events",batch);c.getContentResolver().call(Uri.parse("content://"+SecureProvider.AUTHORITY),"appendHttp",null,data);}
            }
        }catch(Throwable ignored){}
        finally{Handler h=worker;if(h!=null)h.postDelayed(HttpObservationHooks::flush,1500);}
    }
    private static Object call(Object target,String method,Object... args)throws Exception{
        Method m=args.length==0?target.getClass().getMethod(method):target.getClass().getMethod(method,String.class);m.setAccessible(true);return m.invoke(target,args);
    }
    private static DnsObservation.Http describe(Object object){
        try{
            if(object instanceof HttpURLConnection){HttpURLConnection c=(HttpURLConnection)object;
                return DnsObservation.http(c.getURL().toString(),c.getRequestMethod(),c.getRequestProperty("Content-Type"));}
            Object request=call(object,"request");return DnsObservation.http(String.valueOf(call(request,"url")),String.valueOf(call(request,"method")),(String)call(request,"header","Content-Type"));
        }catch(Throwable ignored){return null;}
    }
    public static void install(XposedInterface api,ClassLoader loader){
        try{
            Method attach=android.app.Application.class.getDeclaredMethod("attach",Context.class);
            synchronized(hooked){if(hooked.add(attach))api.hook(attach).setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE).intercept(chain->{Object result=chain.proceed();try{attach((Context)chain.getArg(0));}catch(Throwable ignored){}return result;});}
        }catch(Throwable ignored){}
        for(String cls:new String[]{"com.android.okhttp.internal.huc.HttpURLConnectionImpl","com.android.okhttp.internal.huc.HttpsURLConnectionImpl","okhttp3.RealCall","okhttp3.internal.connection.RealCall"}){
            try{Class<?> type=Class.forName(cls,false,loader);
                for(Method method:type.getDeclaredMethods()){
                    String name=method.getName();
                    if(!(name.equals("connect")||name.equals("getInputStream")||name.equals("getOutputStream")||name.equals("execute")||name.equals("enqueue"))||Modifier.isAbstract(method.getModifiers()))continue;
                    synchronized(hooked){if(!hooked.add(method))continue;}
                    api.hook(method).setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE).intercept(chain->{
                        if(inside.get()||(configAt>0&&!enabled))return chain.proceed();
                        inside.set(true);DnsObservation.Http h=null;
                        try{
                            try{h=describe(chain.getThisObject());}catch(Throwable ignored){}
                            Object result;
                            try{result=chain.proceed();}
                            catch(Throwable error){try{submit(h,"API 抛出 "+error.getClass().getSimpleName());}catch(Throwable ignored){}throw error;}
                            try{submit(h,"API "+name+" 返回；不代表 DNS 查询成功");}catch(Throwable ignored){}
                            return result;
                        }finally{inside.set(false);}
                    });
                }
            }catch(Throwable ignored){}
        }
    }
}
