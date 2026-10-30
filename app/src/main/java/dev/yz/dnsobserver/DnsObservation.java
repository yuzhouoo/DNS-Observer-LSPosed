package dev.yz.dnsobserver;

import java.net.URI;
import java.net.URLDecoder;
import java.util.Locale;

/** Pure evidence classification; API calls/keywords never imply a successful DNS exchange. */
public final class DnsObservation {
    public static final class Http {
        public String host,url,method,transport,evidence,detail;
        public boolean dnsParam;
        public String dnsQuery="";
    }
    public static Http http(String raw,String method,String mime){
        try{
            if(raw==null||raw.length()>8192)return null;
            URI u=new URI(raw);String scheme=u.getScheme(),host=u.getHost();
            if(host==null||!("https".equalsIgnoreCase(scheme)||"http".equalsIgnoreCase(scheme)))return null;
            String path=u.getRawPath()==null?"/":u.getRawPath();
            String lower=path.toLowerCase(Locale.ROOT);String query=u.getRawQuery();
            boolean media=mime!=null&&mime.split(";",2)[0].trim().equalsIgnoreCase("application/dns-message");
            boolean keyword=lower.contains("dns-query")||lower.contains("dnsquery")||lower.contains("/resolve")||lower.contains("/doh");
            boolean dnsParam=false;String name="",dnsQuery="",decodedName="";int decodedType=-1;
            if(query!=null)for(String part:query.split("&")){
                String[] pair=part.split("=",2);
                if(pair[0].equalsIgnoreCase("dns")){
                    dnsParam=true;
                    if(pair.length==2&&pair[1].length()<6000)try{
                        byte[] q=java.util.Base64.getUrlDecoder().decode(URLDecoder.decode(pair[1],"UTF-8"));
                        if(q.length<=4096&&DnsPacket.validQuestion(q)){dnsQuery=java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(q);decodedName=questionName(q);decodedType=questionType(q);}
                    }catch(Exception ignored){}
                }
                if(pair[0].equalsIgnoreCase("name")&&pair.length==2)name=URLDecoder.decode(pair[1],"UTF-8");
            }
            if(!media&&!keyword&&!dnsParam)return null;
            Http h=new Http();h.dnsParam=dnsParam;h.dnsQuery=dnsQuery;h.host=host;h.method=method==null?"UNKNOWN":method;
            // Never retain credentials, fragments, arbitrary query tokens or request bodies.
            h.url=new URI(scheme.toLowerCase(Locale.ROOT),null,host,u.getPort(),u.getPath(),null,null).toASCIIString();
            h.transport=(media||!dnsQuery.isEmpty())?(scheme.equalsIgnoreCase("https")?"DoH":"HTTP_DNS"):"SUSPECTED";
            h.evidence=!dnsQuery.isEmpty()?"HTTP_API_DNS_QUERY":media?"HTTP_API_MEDIA_TYPE":"HTTP_API_KEYWORD";
            h.detail="HTTP 调用观察，非 DNS 回包证据；关键词="+keyword+"；dns 参数="+dnsParam+
                "；GET DNS="+decodedName+" "+(decodedType<0?"":typeName(decodedType))+"; Content-Type="+(media?"application/dns-message":"未观测")+(name.isEmpty()?"":"；name="+name.substring(0,Math.min(253,name.length())));
            return h;
        }catch(Exception ignored){return null;}
    }
    public static String questionName(byte[] q){
        if(!DnsPacket.validQuestion(q))return "";
        StringBuilder b=new StringBuilder();int p=12;
        while(p<q.length){int n=q[p++]&255;if(n==0)return b.toString();if(n>63||p+n>q.length)return "";
            if(b.length()>0)b.append('.');for(int k=0;k<n;k++){int c=q[p++]&255;b.append(c>=33&&c<=126&&c!='|'?(char)c:'?');}}
        return "";
    }
    public static int questionType(byte[] q){
        if(!DnsPacket.validQuestion(q))return -1;int p=12;
        while(p<q.length){int n=q[p++]&255;if(n==0)return p+1<q.length?((q[p]&255)<<8)|(q[p+1]&255):-1;
            if(n>63)return -1;p+=n;}return -1;
    }
    public static String[] answerAddresses(byte[] a){
        java.util.ArrayList<String> found=new java.util.ArrayList<>();
        try{
            if(a==null||a.length<12)return new String[0];int qd=u16(a,4),an=u16(a,6),p=12;
            if(qd>16||an>128)return new String[0];
            for(int k=0;k<qd;k++){p=skipName(a,p);if(p<0||p+4>a.length)return new String[0];p+=4;}
            for(int k=0;k<an&&found.size()<10;k++){
                p=skipName(a,p);if(p<0||p+10>a.length)break;
                int type=u16(a,p),klass=u16(a,p+2),length=u16(a,p+8);p+=10;if(p+length>a.length)break;
                if(klass==1&&((type==1&&length==4)||(type==28&&length==16)))
                    found.add(java.net.InetAddress.getByAddress(java.util.Arrays.copyOfRange(a,p,p+length)).getHostAddress());
                p+=length;
            }
        }catch(Exception ignored){}
        return found.toArray(new String[0]);
    }
    private static int u16(byte[] a,int p){return ((a[p]&255)<<8)|(a[p+1]&255);}
    private static int skipName(byte[] a,int p){
        for(int k=0;k<128&&p<a.length;k++){int n=a[p++]&255;if(n==0)return p;
            if((n&192)==192)return p<a.length&&(((n&63)<<8)|(a[p]&255))<a.length?p+1:-1;
            if(n>63||p+n>a.length)return -1;p+=n;}return -1;
    }
    public static String typeName(int type){return type==1?"A":type==28?"AAAA":type==5?"CNAME":type==65?"HTTPS":type==64?"SVCB":"TYPE"+type;}
}
