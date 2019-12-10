package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.DnsPacket;

import java.net.InetAddress;

public class DnsPacketHandler extends PacketHandler {
    public DnsPacketHandler(DnsPacket packet) {
        super(packet.getPayload());
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.dns;
    }

    @Override
    public InetAddress sourceAddress() {
        return null;
    }

    @Override
    public int sourcePort() {
        return -1;
    }

    @Override
    public InetAddress destinationAddress() {
        return null;
    }

    @Override
    public int destinationPort() {
        return -1;
    }
}
