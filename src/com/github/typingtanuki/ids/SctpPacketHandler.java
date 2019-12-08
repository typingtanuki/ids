package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.SctpPacket;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;

public class SctpPacketHandler extends PacketHandler {
    private SctpPacket packet;

    public SctpPacketHandler(SctpPacket packet) {
        super();
        this.packet = packet;
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.sctp;
    }

    @Override
    public InetAddress sourceAddress() {
        throw new NotImplementedException();
    }

    @Override
    public int sourcePort() {
        return packet.getHeader().getSrcPort().value();
    }

    @Override
    public InetAddress destinationAddress() {
        throw new NotImplementedException();
    }

    @Override
    public int destinationPort() {
        return packet.getHeader().getDstPort().value();
    }

    @Override
    public TcpPacket.TcpHeader getTcpHeader() {
        throw new NotImplementedException();
    }
}
