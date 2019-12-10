package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.exceptions.IdsException;
import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.snort.SnortMatcher;
import com.github.typingtanuki.ids.snort.SnortRule;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;

public class PcapMonitor extends Thread implements PacketListener {
    private static final Logger logger = LoggerFactory.getLogger(PcapMonitor.class);

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
        } catch (IdsException | InterruptedException e) {
            logger.error("Error during packet capture, stopping.", e);
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

    public void handlePackets() throws IdsException {
        List<Packet> previous;
        synchronized (this) {
            previous = packets;
            packets = new LinkedList<>();
        }

        for (Packet packet : previous) {
            PacketInfo packetInfo = new PacketInfo(packet);

            try {
                List<SnortRule> matches = snort.match(packetInfo);
                int counter = 1;
                if (!matches.isEmpty()) {
                    logger.warn("-------------------------------------");
                    logger.warn("DANGER ! matched {}", matches.size());
                    logger.warn("{}", packetInfo);
                    for (SnortRule match : matches) {
                        logger.warn("{}) {}", counter, match);
                        counter++;
                    }
                    logger.warn("-------------------------------------");
                }
            } catch (SnortException | RuntimeException e) {
                throw new IdsException("Error matching packet", e);
            }
        }
    }

    public void stopNow() {
        this.interrupt();
    }
}
