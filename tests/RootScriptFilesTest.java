package dev.yz.dnsobserver;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class RootScriptFilesTest {
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("dns-script-update");
        File assets=Files.createDirectory(root.resolve("assets")).toFile();
        File files=Files.createDirectory(root.resolve("files")).toFile();
        android.content.Context ctx=new android.content.Context(files,assets);
        byte[] old="#!/bin/sh\necho old\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] updated="#!/bin/sh\necho new\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Files.write(assets.toPath().resolve("root.sh"),old);
        File installed=RootScriptFiles.install(ctx,"root.sh","cached.sh");
        if(!Arrays.equals(old,Files.readAllBytes(installed.toPath())))throw new AssertionError("first install");
        try(InputStream running=Files.newInputStream(installed.toPath())){
            Files.write(assets.toPath().resolve("root.sh"),updated);
            RootScriptFiles.install(ctx,"root.sh","cached.sh");
            if(!Arrays.equals(updated,Files.readAllBytes(installed.toPath())))throw new AssertionError("APK update must refresh same-size obsolete script");
            if(!Arrays.equals(old,running.readAllBytes()))throw new AssertionError("already running script inode must remain intact");
        }
        RootScriptFiles.install(ctx,"root.sh","cached.sh");
        if(Files.exists(files.toPath().resolve("cached.sh.new")))throw new AssertionError("temporary file remains");
        Files.delete(installed.toPath());Files.delete(assets.toPath().resolve("root.sh"));
        Files.delete(files.toPath());Files.delete(assets.toPath());Files.delete(root);
        System.out.println("PASS: updated APK replaces cached Root script atomically, including same-size changes");
    }
}
