package dev.yz.dnsobserver;

/** Display state comes from observation plus lifecycle, never from a request flag alone. */
public enum DnsFeatureState {
    UNKNOWN("待确认"), OFF("已关闭"), STARTING("正在开启"), ON("已开启"), STOPPING("正在关闭"), ERROR("异常");
    public final String label;
    DnsFeatureState(String label) { this.label=label; }
    public static DnsFeatureState resolve(String phase, boolean selected, boolean requested,
                                          boolean known, boolean present, boolean verified) {
        if("stopping".equals(phase))return STOPPING;
        if("starting".equals(phase) && selected)return STARTING;
        if(!known)return UNKNOWN;
        if(verified)return ON;
        if(present || (requested && selected))return ERROR;
        return OFF;
    }
    public static boolean mayStart(boolean requested, String phase, boolean busy, boolean configReady,
                                   boolean select4, boolean select6, DnsFeatureState v4,
                                   DnsFeatureState v6, String systemIpv6) {
        if(requested || !"idle".equals(phase) || busy || !configReady || (!select4&&!select6))return false;
        // Unknown or residual rules require an explicit check/cleanup before installing new rules.
        if(v4!=OFF || v6!=OFF)return false;
        return !select6 || "enabled".equals(systemIpv6) || "mixed".equals(systemIpv6);
    }
}
