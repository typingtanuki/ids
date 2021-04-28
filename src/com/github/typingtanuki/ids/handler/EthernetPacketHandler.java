package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public class EthernetPacketHandler extends PacketHandler<EthernetPacket> {
    public EthernetPacketHandler(EthernetPacket packet) {
        super(packet, SnortProtocol.ethernet);
    }

    @Override
    public InetAddress sourceAddress() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).sourceAddress();
    }

    @Override
    public int sourcePort() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).sourcePort();
    }

    @Override
    public InetAddress destinationAddress() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).destinationAddress();
    }

    @Override
    public int destinationPort() throws OperationNotSupportedException {
        return getSubHandler(Packet.class).destinationPort();
    }
}
