package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.*;

import java.net.InetAddress;

public abstract class PacketHandler {
    public static PacketHandler from(Packet packet) throws SnortException {
        if (packet instanceof TransportPacket) {
            return fromTransport((TransportPacket) packet);
        }
        if (packet instanceof EthernetPacket) {
            return new EthernetPacketHandler((EthernetPacket) packet);
        }
        if (packet instanceof ArpPacket) {
            return new ArpPacketHandler((ArpPacket) packet);
        }
        if (packet instanceof IpV4Packet) {
            return new Ipv4PacketHandler((IpV4Packet) packet);
        }
        if (packet instanceof IpV6Packet) {
            return new Ipv6PacketHandler((IpV6Packet) packet);
        }
        if (packet instanceof IcmpV6CommonPacket) {
            return new IcmpPacketHandler((IcmpV6CommonPacket) packet);
        }
        if (packet instanceof IcmpV6NeighborSolicitationPacket) {
            return new IcmpPacketHandler((IcmpV6NeighborSolicitationPacket) packet);
        }
        if (packet instanceof UnknownPacket) {
            return new UnknownPacketHandler(packet);
        }
        throw new SnortException("Unknown packet type " + packet.getClass().getSimpleName());
    }

    private static PacketHandler fromTransport(TransportPacket packet) throws SnortException {
        if (packet instanceof TcpPacket) {
            return new TcpPacketHandler((TcpPacket) packet);
        }
        if (packet instanceof UdpPacket) {
            return new UdpPacketHandler((UdpPacket) packet);
        }
        if (packet instanceof SctpPacket) {
            return new SctpPacketHandler((SctpPacket) packet);
        }
        throw new SnortException("Unknown packet type " + packet.getClass().getSimpleName());
    }


    public abstract SnortProtocol getProtocol();

    public abstract InetAddress sourceAddress();

    public abstract int sourcePort();

    public abstract InetAddress destinationAddress();

    public abstract int destinationPort();

    public abstract TcpPacket.TcpHeader getTcpHeader();
}
