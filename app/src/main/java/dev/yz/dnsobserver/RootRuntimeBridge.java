package dev.yz.dnsobserver;

import android.content.Context;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/** Fixed Root command surface. No arbitrary shell text from UI or imported profiles. */
public final class RootRuntimeBridge {
    public static final String BIN="/data/adb/yutong/bin/yutong";
    public static boolean selected(Context c){return c.getSharedPreferences(DnsForwardService.PREFS,0).getBoolean("module_backend",false);}
    public static JSONObject call(String operation,String... args)throws Exception{return execute(operation,null,args);}
    public static JSONObject upload(String operation,InputStream input)throws Exception{return execute(operation,input);}
    private static JSONObject execute(String operation,InputStream input,String... args)throws Exception{
        if(!operation.matches("status|logs|apply|cleanup|proxies|select|import-config|import-core"))throw new IllegalArgumentException("Unknown Root operation");
        StringBuilder cmd=new StringBuilder(BIN).append(' ').append(operation);
        for(String a:args){if(!a.matches("[A-Za-z0-9+/=]*"))throw new IllegalArgumentException("Invalid encoded argument");cmd.append(' ').append(a);}
        java.lang.Process p=new ProcessBuilder("su","-c",cmd.toString()).redirectErrorStream(true).start();
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        Thread drain=new Thread(()->{try(InputStream in=p.getInputStream()){byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1)synchronized(bytes){if(bytes.size()<3*1024*1024)bytes.write(b,0,Math.min(n,3*1024*1024-bytes.size()));}}catch(Exception ignored){}},"YuTong-root-output");drain.setDaemon(true);drain.start();
        Thread writer=new Thread(()->{try(java.io.OutputStream out=p.getOutputStream()){if(input!=null){byte[] b=new byte[65536];int n;while((n=input.read(b))!=-1)out.write(b,0,n);}}catch(Exception ignored){}},"YuTong-root-upload");writer.setDaemon(true);writer.start();
        if(!p.waitFor(input==null?20:120,TimeUnit.SECONDS)){p.destroyForcibly();throw new IllegalStateException("Root 后台命令超时: "+operation);}
        drain.join(1000);writer.join(1000);String text; synchronized(bytes){text=bytes.toString(StandardCharsets.UTF_8.name()).trim();}
        JSONObject result;try{result=new JSONObject(text);}catch(Exception e){throw new IllegalStateException(text.isEmpty()?"模块后台未安装或无输出":text);}
        if(p.exitValue()!=0||result.has("error"))throw new IllegalStateException(result.optString("error",text));return result;
    }
    public static String encode(String value){return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));}
}
