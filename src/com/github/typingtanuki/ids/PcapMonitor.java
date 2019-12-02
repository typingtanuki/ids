package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortMatcher;
import com.github.typingtanuki.ids.snort.SnortRule;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

public class PcapMonitor extends Thread implements PacketListener {
    private static final int READ_TIMEOUT = 10; // [ms]
    private static final int SNAPLEN = 65536; // [bytes]

    //    private static final int INFINITE = -1;
    private static final int PACKET_COUNT = 10;
    // BPF filter for capturing any packet
    private static final String FILTER = "";

    private int m_counter = 0;

    private PcapNetworkInterface device;
    private SnortMatcher snort;
    private PcapHandle handle;
    private List<Packet> packets = new LinkedList<>();

    public PcapMonitor(PcapNetworkInterface device, SnortMatcher snort) throws IdsException {
        this.device = device;
        this.snort = snort;
        initDevice(device);
    }

    private PcapHandle initDevice(PcapNetworkInterface device) throws IdsException {
        try {
            handle = device.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
            handle.setFilter(FILTER, BpfProgram.BpfCompileMode.OPTIMIZE);
            return handle;
        } catch (PcapNativeException e) {
            throw new IdsException("Error setting up device " + device, e);
        } catch (NotOpenException e) {
            throw new IdsException("Error setting up filter " + FILTER + " on device " + device, e);
        }
    }

    public void run() {
        try {
            while (!interrupted()) {
                loop();
            }
        } catch (IdsException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
            interrupt();
        }
    }

    private void loop() throws IdsException, InterruptedException {
        try {
            handle.loop(PACKET_COUNT, this);
        } catch (NotOpenException | PcapNativeException e) {
            throw new IdsException("Error during capture", e);
        }

    }

    @Override
    public synchronized void gotPacket(Packet packet) {
        this.packets.add(packet);
    }

    public synchronized boolean hasData() {
        return !packets.isEmpty();
    }

    public void print() throws IdsException {
        List<Packet> previous;
        synchronized (this) {
            previous = packets;
            packets = new LinkedList<>();
        }

        for (Packet packet : previous) {
            PacketMetadata metadata = new PacketMetadata();
            handlePacket(packet, metadata);

            try {
                if (!metadata.isEmpty()) {
                    List<SnortRule> matches = snort.match(metadata);
                    int counter = 1;
                    if (!matches.isEmpty()) {
                        System.out.println("-------------------------------------");
                        System.out.println("DANGER ! matched " + matches.size());
                        System.out.println(metadata);
                        for (SnortRule match : matches) {
                            System.out.println(counter + ") " + match);
                            counter++;
                        }
                        System.out.println("-------------------------------------");
                    }
                }
            } catch (SnortException | RuntimeException e) {
                throw new IdsException("Error matching packet", e);
            }
        }
    }

    private void handlePacket(Packet packet, PacketMetadata metadata) throws IdsException {
        Packet.Header header = packet.getHeader();
        handleHeader(header, metadata);
        Packet payload = packet.getPayload();
        if (payload != null) {
            metadata.setData(payload.getRawData());
            handlePacket(payload, metadata);
        }
    }

    private void handleHeader(Packet.Header header, PacketMetadata metadata) throws IdsException {
        if (header == null) {
            return;
        }

        if (header instanceof EthernetPacket.EthernetHeader) {
            return;
        }
        if (header instanceof IpPacket.IpHeader) {
            IpPacket.IpHeader ipHeader = (IpPacket.IpHeader) header;
            metadata.setSrcAddr(ipHeader.getSrcAddr());
            metadata.setDstAddr(ipHeader.getDstAddr());
            metadata.setProtocol(ipHeader.getProtocol().name().toLowerCase(Locale.ENGLISH));
            return;
        }
        if (header instanceof TransportPacket.TransportHeader) {
            TransportPacket.TransportHeader transportHeader = (TransportPacket.TransportHeader) header;
            metadata.setSrcPort(transportHeader.getSrcPort().valueAsInt());
            metadata.setDstPort(transportHeader.getDstPort().valueAsInt());

            handleTransportHeader(transportHeader, metadata);
            return;
        }
        if (header instanceof ArpPacket.ArpHeader) {
            ArpPacket.ArpHeader arpHeader = (ArpPacket.ArpHeader) header;
            metadata.setSrcAddr(arpHeader.getSrcProtocolAddr());
            metadata.setDstAddr(arpHeader.getDstProtocolAddr());
            metadata.setProtocol("arp");
            return;
        }
        if (header instanceof DnsPacket.DnsHeader) {
            metadata.setProtocol("dns");
            return;
        }
        if (header instanceof IcmpV4CommonPacket.IcmpV4CommonHeader) {
            metadata.setProtocol("icmp");
            return;
        }
        if (header instanceof IcmpV6CommonPacket.IcmpV6CommonHeader ||
                header instanceof IcmpV6NeighborSolicitationPacket.IcmpV6NeighborSolicitationHeader) {
            metadata.setProtocol("icmp");
            return;
        }
        throw new IdsException("Unknown header format: " + header.getClass().getSimpleName(), null);
    }

    private void handleTransportHeader(TransportPacket.TransportHeader transportHeader, PacketMetadata metadata) {
        if (transportHeader instanceof TcpPacket.TcpHeader) {
            TcpPacket.TcpHeader tcpHeader = (TcpPacket.TcpHeader) transportHeader;
            metadata.setTcpFlagSequenceNumber(tcpHeader.getSequenceNumberAsLong());
            metadata.setTcpFlagAcknowledgmentNumber(tcpHeader.getAcknowledgmentNumberAsLong());
            metadata.setTcpFlagDataOffset(tcpHeader.getDataOffsetAsInt());
            metadata.setTcpFlagReserved(tcpHeader.getReserved());
            metadata.setTcpFlagUrg(tcpHeader.getUrg());
            metadata.setTcpFlagAck(tcpHeader.getAck());
            metadata.setTcpFlagPsh(tcpHeader.getPsh());
            metadata.setTcpFlagRst(tcpHeader.getRst());
            metadata.setTcpFlagSyn(tcpHeader.getSyn());
            metadata.setTcpFlagFin(tcpHeader.getFin());
            metadata.setTcpFlagWindow(tcpHeader.getWindowAsInt());
            metadata.setTcpFlagChecksum(tcpHeader.getChecksum());
            metadata.setTcpFlagUrgentPointer(tcpHeader.getUrgentPointerAsInt());
        }
    }
}
