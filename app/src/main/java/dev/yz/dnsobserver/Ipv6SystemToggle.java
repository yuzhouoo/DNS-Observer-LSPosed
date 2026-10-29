package dev.yz.dnsobserver;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Root-only immediate toggle for existing IPv6 interfaces. */
public final class Ipv6SystemToggle {
    private Ipv6SystemToggle() {}
    public static String set(boolean disable) throws Exception {
        String script =
            "set -eu\n" +
            "dir=/proc/sys/net/ipv6/conf\n" +
            "state=/data/local/tmp/dnsobserver-ipv6-original\n" +
            "[ -d \"$dir\" ] || exit 2\n" +
            "case \"$1\" in\n" +
            " on)\n" +
            "  if [ ! -f \"$state\" ]; then\n" +
            "   umask 077; tmp=\"$state.tmp.$$\"; : > \"$tmp\"\n" +
            "   for f in \"$dir\"/*/disable_ipv6; do [ -f \"$f\" ] || continue; printf '%s %s\\n' \"$f\" \"$(cat \"$f\")\" >> \"$tmp\"; done\n" +
            "   mv \"$tmp\" \"$state\"\n" +
            "  fi\n" +
            "  for f in \"$dir\"/*/disable_ipv6; do [ -f \"$f\" ] || continue; echo 1 > \"$f\"; done\n" +
            "  for f in \"$dir\"/*/disable_ipv6; do [ -f \"$f\" ] || continue; [ \"$(cat \"$f\")\" = 1 ] || exit 3; done\n" +
            "  echo IPV6_DISABLED;;\n" +
            " off)\n" +
            "  [ -f \"$state\" ] || { echo NO_SAVED_STATE; exit 4; }\n" +
            "  while read -r f value; do [ -f \"$f\" ] || continue; case \"$value\" in 0|1) echo \"$value\" > \"$f\";; *) exit 5;; esac; done < \"$state\"\n" +
            "  while read -r f value; do [ -f \"$f\" ] || continue; [ \"$(cat \"$f\")\" = \"$value\" ] || exit 6; done < \"$state\"\n" +
            "  rm -f \"$state\"; echo IPV6_RESTORED;;\n" +
            " *) exit 7;; esac\n";
        String command="sh -c '"+script.replace("'", "'\\''")+"' -- "+(disable?"on":"off");
        Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try(InputStream in=process.getInputStream()){
            byte[] buf=new byte[1024];int n;
            while((n=in.read(buf))!=-1) if(out.size()<8192)out.write(buf,0,Math.min(n,8192-out.size()));
        }
        int rc=process.waitFor();
        String result=out.toString(StandardCharsets.UTF_8.name()).trim();
        if(rc!=0)throw new IllegalStateException("Root rc="+rc+" "+result);
        return result;
    }
}
