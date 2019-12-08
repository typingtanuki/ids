package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;

public class TcpPacketHandler extends PacketHandler {
    private TcpPacket packet;

    public TcpPacketHandler(TcpPacket packet) {
        super();
        this.packet = packet;
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.tcp;
    }

    @Override
    public InetAddress sourceAddress() {
        return null;
    }

    @Override
    public int sourcePort() {
        return packet.getHeader().getSrcPort().value();
    }

    @Override
    public InetAddress destinationAddress() {
        return null;
    }

    @Override
    public int destinationPort() {
        return packet.getHeader().getDstPort().value();
    }

    public TcpPacket.TcpHeader getTcpHeader() {
        return packet.getHeader();
    }
}
