package com.github.typingtanuki.ids.snort;

public enum SnortProtocol {
    icmp,
    tcp,
    all,
    udp,
    dns,
    arp,
    igmp, unknown;

    public static SnortProtocol from(String protocol) {
        if (protocol == null) {
            return SnortProtocol.unknown;
        }
        try {
            return SnortProtocol.valueOf(protocol);
        } catch (IllegalArgumentException e) {
            System.out.println("Unknown protocol " + protocol);
            return SnortProtocol.unknown;
        }
    }
}
