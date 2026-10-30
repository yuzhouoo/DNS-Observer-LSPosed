package dev.yz.dnsobserver;

import android.content.Context;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedInterface;

/**
 * LSPosed Modern API 102: System Framework events plus optional user-selected Java HTTP scopes.
 * Observes resolver events, never replaces or modifies any DNS result.
 */
public final class ModernHookEntry extends XposedModule {
    private static final String TAG = "DNSObserver";
    private boolean systemServer;

    public ModernHookEntry() { }

    @Override public void onModuleLoaded(ModuleLoadedParam param) {
        systemServer = param.isSystemServer();
        report("module loaded; process=" + param.getProcessName()
                + ", systemServer=" + systemServer + ", API=" + getApiVersion());
    }

    @Override public void onSystemServerStarting(SystemServerStartingParam param) {
        if (!systemServer) return;
        report("system server starting");
        ClassLoader loader = param.getClassLoader();
        // Independent installation: failure of one hook must not disable the other.
        installLifecycleHooks(loader);
        installDnsHook(loader);
        installAuxiliaryHooks(loader);
        HttpObservationHooks.install(this,loader);
    }

    @Override public void onPackageReady(PackageReadyParam param){
        if(!systemServer && !"dev.yz.dnsobserver".equals(param.getPackageName()))
            HttpObservationHooks.install(this,param.getClassLoader());
    }
    private void installAuxiliaryHooks(ClassLoader loader){
        try{Class<?> listener=Class.forName("com.android.server.connectivity.NetdEventListenerService",false,loader);
            for(Method method:listener.getDeclaredMethods()){
                Class<?>[] t=method.getParameterTypes();String n=method.getName();
                boolean connection=n.equals("onConnectEvent")&&java.util.Arrays.equals(t,new Class<?>[]{int.class,int.class,int.class,String.class,int.class,int.class});
                boolean validation=n.equals("onPrivateDnsValidationEvent")&&java.util.Arrays.equals(t,new Class<?>[]{int.class,String.class,String.class,boolean.class});
                if(!connection&&!validation)continue;
                hook(method).setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE).intercept(chain->{
                    Object result=chain.proceed();try{
                        if(connection)EventCollector.get().connection((Integer)chain.getArg(0),(Integer)chain.getArg(1),(Integer)chain.getArg(2),(String)chain.getArg(3),(Integer)chain.getArg(4),(Integer)chain.getArg(5));
                        else EventCollector.get().validation((Integer)chain.getArg(0),(String)chain.getArg(1),(String)chain.getArg(2),(Boolean)chain.getArg(3));
                    }catch(Throwable ignored){}return result;
                });
                report("auxiliary hook installed: "+n);
            }
        }catch(Throwable error){report("optional auxiliary hooks unavailable: "+error.getClass().getSimpleName());}
    }
    private void installLifecycleHooks(ClassLoader loader) {
        try {
            Class<?> systemServerClass =
                    Class.forName("com.android.server.SystemServer", false, loader);
            int installed = 0;
            for (String name : new String[]{"createSystemContext", "startBootstrapServices",
                    "startOtherServices"}) {
                for (Method method : systemServerClass.getDeclaredMethods()) {
                    if (!name.equals(method.getName())) continue;
                    try {
                        hook(method)
                            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                            .intercept(chain -> {
                                // Preserve exceptions and return values from system services.
                                Object original = chain.proceed();
                                try {
                                    Object instance = chain.getThisObject();
                                    if (instance == null) return original;
                                    Field field = instance.getClass().getDeclaredField("mSystemContext");
                                    field.setAccessible(true);
                                    Object ctx = field.get(instance);
                                    if (ctx instanceof Context) {
                                        EventCollector.get().start((Context) ctx);
                                    }
                                } catch (Throwable t) {
                                    report("context not ready: " + t.getClass().getSimpleName());
                                }
                                return original;
                            });
                        installed++;
                    } catch (Throwable t) {
                        report("lifecycle hook failed " + name + ": " + t);
                    }
                }
            }
            report("lifecycle hooks installed=" + installed);
        } catch (Throwable t) {
            report("SystemServer lifecycle unavailable: " + t);
        }
    }

    private void installDnsHook(ClassLoader loader) {
        try {
            Class<?> listener = Class.forName(
                    "com.android.server.connectivity.NetdEventListenerService", false, loader);
            int installed = 0;
            for (Method method : listener.getDeclaredMethods()) {
                if (!"onDnsEvent".equals(method.getName())) continue;
                Class<?>[] types = method.getParameterTypes();
                if (types.length != 8 || types[0] != int.class || types[1] != int.class
                        || types[2] != int.class || types[3] != int.class
                        || types[4] != String.class || types[5] != String[].class
                        || types[6] != int.class || types[7] != int.class) continue;
                hook(method)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        Object original = chain.proceed();
                        try {
                            EventCollector.get().accept(
                                (Integer) chain.getArg(0), (Integer) chain.getArg(1),
                                (Integer) chain.getArg(2), (Integer) chain.getArg(3),
                                (String) chain.getArg(4), (String[]) chain.getArg(5),
                                (Integer) chain.getArg(6), (Integer) chain.getArg(7));
                        } catch (Throwable ignored) {
                            // Never interfere with system DNS functionality.
                        }
                        return original;
                    });
                installed++;
            }
            report(installed > 0 ? "DNS event hooks installed=" + installed
                    : "DNS onDnsEvent signature not found");
        } catch (Throwable t) {
            report("DNS event hook unavailable: " + t);
        }
    }

    private void report(String message) {
        // Xposed log and logcat both carry the exact searchable prefix.
        log(Log.INFO, TAG, "DNSObserver: " + message);
        Log.i(TAG, "DNSObserver: " + message);
    }
}
