package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.DnsPacket;

import java.net.InetAddress;

public class DnsPacketHandler extends PacketHandler<DnsPacket> {
    public DnsPacketHandler(DnsPacket packet) {
        super(packet, SnortProtocol.dns);
    }

    @Override
    public InetAddress sourceAddress() {
        return null;
    }

    @Override
    public int sourcePort() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noSourcePort(getProtocol());
    }

    @Override
    public InetAddress destinationAddress() {
        return null;
    }

    @Override
    public int destinationPort() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noDestinationPort(getProtocol());
    }
}
