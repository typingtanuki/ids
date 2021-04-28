package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public class ArpPacketHandler extends PacketHandler<ArpPacket> {
    public ArpPacketHandler(ArpPacket packet) {
        super(packet, SnortProtocol.arp);
    }

    @Override
    public InetAddress sourceAddress() {
        return packet.getHeader().getSrcProtocolAddr();
    }

    @Override
    public int sourcePort() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return packet.getHeader().getDstProtocolAddr();
    }

    @Override
    public int destinationPort() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).destinationPort();
    }
}
