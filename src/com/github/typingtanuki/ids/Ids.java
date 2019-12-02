package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortMatcher;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.ArrayList;
import java.util.List;

public class Ids extends Thread {
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
        } catch (IdsException e) {
            e.printStackTrace();
        }
    }

    private void capture() throws IdsException {
        for (PcapMonitor monitor : pcaps) {
            if (monitor.hasData()) {
                monitor.print();
            }
        }
    }

    private void init() throws IdsException {
        try {
            devices = Pcaps.findAllDevs();
            pcaps = initDevices();
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

