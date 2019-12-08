package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;

public class Ipv6PacketHandler  extends PacketHandler {

    private final PacketHandler subHandler;
    private final IpV6Packet packet;

    public Ipv6PacketHandler(IpV6Packet packet) throws SnortException {
        super();
        this.subHandler = PacketHandler.from(packet.getPayload());
        this.packet = packet;
    }


    @Override
    public SnortProtocol getProtocol() {
        return subHandler.getProtocol();
    }

    @Override
    public InetAddress sourceAddress() {
        return packet.getHeader().getSrcAddr();
    }

    @Override
    public int sourcePort() {
        return subHandler.sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return packet.getHeader().getDstAddr();
    }

    @Override
    public int destinationPort() {
        return subHandler.destinationPort();
    }

    @Override
    public TcpPacket.TcpHeader getTcpHeader() {
        return subHandler.getTcpHeader();
    }
}
