package com.github.typingtanuki.ids.handler;

import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketHandlers {
    public static Logger logger = LoggerFactory.getLogger(PacketHandlers.class);

    public static PacketHandler from(Packet packet) {
        if (packet instanceof TransportPacket) {
            return fromTransport((TransportPacket) packet);
        }
        if (packet instanceof IpPacket) {
            return new IpPacketHandler((IpPacket) packet);
        }
        if (packet instanceof EthernetPacket) {
            return new EthernetPacketHandler((EthernetPacket) packet);
        }
        if (packet instanceof ArpPacket) {
            return new ArpPacketHandler((ArpPacket) packet);
        }
        if (packet instanceof IcmpV6CommonPacket) {
            return new IcmpPacketHandler((IcmpV6CommonPacket) packet);
        }
        if (packet instanceof IcmpV6NeighborSolicitationPacket) {
            return new IcmpPacketHandler((IcmpV6NeighborSolicitationPacket) packet);
        }
        if (packet instanceof IcmpV4CommonPacket) {
            return new IcmpPacketHandler((IcmpV4CommonPacket) packet);
        }
        if (packet instanceof IcmpV4EchoPacket) {
            return new IcmpPacketHandler((IcmpV4EchoPacket) packet);
        }
        if (packet instanceof IcmpV4EchoReplyPacket) {
            return new IcmpPacketHandler((IcmpV4EchoReplyPacket) packet);
        }
        if (packet instanceof UnknownPacket) {
            return new UnknownPacketHandler(packet);
        }
        if (packet instanceof DnsPacket) {
            return new DnsPacketHandler((DnsPacket) packet);
        }
        logger.warn("Unknown packet type {}", packet.getClass().getSimpleName());
        return new UnknownPacketHandler(packet);
    }

    private static PacketHandler fromTransport(TransportPacket packet) {
        if (packet instanceof TcpPacket) {
            return new TcpPacketHandler((TcpPacket) packet);
        }
        if (packet instanceof UdpPacket) {
            return new UdpPacketHandler((UdpPacket) packet);
        }
        logger.warn("Unknown transport packet type {}", packet.getClass().getSimpleName());
        return new UnknownPacketHandler(packet);
    }
}
