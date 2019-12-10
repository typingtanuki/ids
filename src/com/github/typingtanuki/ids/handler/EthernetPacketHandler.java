package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.EthernetPacket;

import java.net.InetAddress;

public class EthernetPacketHandler extends PacketHandler {
    public EthernetPacketHandler(EthernetPacket packet) {
        super(packet.getPayload());
    }

    @Override
    public SnortProtocol getProtocol() {
        return subHandler.getProtocol();
    }

    @Override
    public InetAddress sourceAddress() {
        return subHandler.sourceAddress();
    }

    @Override
    public int sourcePort() {
        return subHandler.sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return subHandler.destinationAddress();
    }

    @Override
    public int destinationPort() {
        return subHandler.destinationPort();
    }
}
