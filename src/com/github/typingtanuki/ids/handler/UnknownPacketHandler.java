package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public class UnknownPacketHandler<T extends Packet> extends PacketHandler<T> {
    public UnknownPacketHandler(T packet) {
        super(packet, SnortProtocol.unknown);
    }

    @Override
    public InetAddress sourceAddress() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noSourceAddress(getProtocol());
    }

    @Override
    public int sourcePort() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noSourcePort(getProtocol());

    }

    @Override
    public InetAddress destinationAddress() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noDestinationAddress(getProtocol());

    }

    @Override
    public int destinationPort() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noDestinationPort(getProtocol());
    }
}
