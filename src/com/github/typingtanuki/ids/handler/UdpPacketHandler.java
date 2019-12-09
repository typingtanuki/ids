package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.net.InetAddress;

public class UdpPacketHandler extends PacketHandler {
    private UdpPacket packet;

    public UdpPacketHandler(UdpPacket packet) {
        super();
        this.packet = packet;
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.udp;
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

    @Override
    public TcpPacket.TcpHeader getTcpHeader() {
        throw new RuntimeException("Wrong protocol");
    }
}
