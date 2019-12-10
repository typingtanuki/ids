package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.ArpPacket;

import java.net.InetAddress;

public class ArpPacketHandler extends PacketHandler {
    private ArpPacket packet;

    public ArpPacketHandler(ArpPacket packet) {
        super(packet.getPayload());
        this.packet = packet;
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.arp;
    }

    @Override
    public InetAddress sourceAddress() {
        return packet.getHeader().getSrcProtocolAddr();
    }

    @Override
    public int sourcePort() {
        if (subHandler == null) {
            return -1;
        }
        return subHandler.sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return packet.getHeader().getDstProtocolAddr();
    }

    @Override
    public int destinationPort() {
        if (subHandler == null) {
            return -1;
        }
        return subHandler.destinationPort();
    }
}
