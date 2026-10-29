package dev.yz.dnsobserver;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Arrays;

/** Replace obsolete extracted scripts atomically after APK updates. */
final class RootScriptFiles {
    private RootScriptFiles() { }
    static synchronized File install(Context ctx,String asset,String name)throws Exception {
        byte[] expected;
        try(InputStream in=ctx.getAssets().open(asset);ByteArrayOutputStream bytes=new ByteArrayOutputStream()){
            byte[] b=new byte[4096];int n;
            while((n=in.read(b))!=-1)bytes.write(b,0,n);
            expected=bytes.toByteArray();
        }
        File file=new File(ctx.getFilesDir(),name);
        if(file.isFile()&&Arrays.equals(expected,Files.readAllBytes(file.toPath())))return file;
        File temp=new File(ctx.getFilesDir(),name+".new");
        try(FileOutputStream out=new FileOutputStream(temp,false)){out.write(expected);out.getFD().sync();}
        if(!temp.setReadable(true,true)||!temp.setWritable(true,true))throw new IllegalStateException("Root 脚本权限错误");
        if(!temp.renameTo(file))throw new IllegalStateException("无法更新 Root 脚本");
        return file;
    }
}
