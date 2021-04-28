package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public class IpPacketHandler extends PacketHandler<IpPacket> {
    public IpPacketHandler(IpPacket packet) {
        super(packet, SnortProtocol.ip);
    }

    @Override
    public InetAddress sourceAddress() {
        return packet.getHeader().getSrcAddr();
    }

    @Override
    public int sourcePort() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return packet.getHeader().getDstAddr();
    }

    @Override
    public int destinationPort() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).destinationPort();
    }
}
