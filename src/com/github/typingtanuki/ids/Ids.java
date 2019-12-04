package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortMatcher;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class Ids extends Thread {
    private static final Logger logger = LoggerFactory.getLogger(Ids.class);

    private List<PcapNetworkInterface> devices;
    private List<PcapMonitor> pcaps;
    private SnortMatcher snort;

    public Ids(SnortMatcher snort) {
        this.snort = snort;
    }

    public void run() {
        try {
            init();
            while (!interrupted()) {
                capture();
            }
        } catch (IdsException | InterruptedException e) {
            stopPcaps();
            logger.error("Stopping catpure due to error", e);
            Thread.currentThread().interrupt();
        }
    }

    private void stopPcaps() {
        for (PcapMonitor pcap : pcaps) {
            pcap.stopNow();
        }
    }

    private void capture() throws IdsException, InterruptedException {
        boolean hadSomethingToDo = false;
        for (PcapMonitor monitor : pcaps) {
            if (monitor.hasData()) {
                monitor.handlePackets();
                hadSomethingToDo = true;
            }
        }
        if (!hadSomethingToDo) {
            Thread.sleep(100);
        }
    }

    private void init() throws IdsException {
        logger.info("Preparing to listen to packets...");
        try {
            devices = Pcaps.findAllDevs();
            pcaps = initDevices();
            logger.info("Preparing to listen to packets... DONE ({} devices monitored)", pcaps.size());
        } catch (PcapNativeException | RuntimeException e) {
            throw new IdsException("Error during init", e);
        }
    }

    private List<PcapMonitor> initDevices() throws IdsException {
        List<PcapMonitor> handles = new ArrayList<>(devices.size());
        for (PcapNetworkInterface interf : devices) {
            if (isInteresting(interf)) {
                PcapMonitor monitor = new PcapMonitor(interf, snort);
                monitor.start();
                handles.add(monitor);
            }
        }
        return handles;
    }

    private boolean isInteresting(PcapNetworkInterface interf) {
        return !interf.isLoopBack() && !interf.getAddresses().isEmpty();
    }

}

