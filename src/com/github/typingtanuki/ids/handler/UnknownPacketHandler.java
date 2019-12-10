package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public class UnknownPacketHandler extends PacketHandler {
    public UnknownPacketHandler(Packet packet) {
        super(packet.getPayload());
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.unknown;
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
