package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.IpPacket;

import java.net.InetAddress;

public class IpPacketHandler extends PacketHandler {
    private IpPacket packet;

    public IpPacketHandler(IpPacket packet) {
        super(packet.getPayload());
        this.packet = packet;
    }


    @Override
    public SnortProtocol getProtocol() {
        return subHandler.getProtocol();
    }

    @Override
    public InetAddress sourceAddress() {
        return packet.getHeader().getSrcAddr();
    }

    @Override
    public int sourcePort() {
        return subHandler.sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return packet.getHeader().getDstAddr();
    }

    @Override
    public int destinationPort() {
        return subHandler.destinationPort();
    }
}
