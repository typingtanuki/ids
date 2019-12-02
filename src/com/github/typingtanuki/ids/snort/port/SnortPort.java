package com.github.typingtanuki.ids.snort.port;

import com.github.typingtanuki.ids.snort.SnortException;

import java.util.ArrayList;
import java.util.List;

public abstract class SnortPort {
    public static SnortPort of(String value) throws SnortException {
        String s = value;
        boolean isNot = false;
        if (s.startsWith("!")) {
            isNot = true;
            s = s.substring(1);
        }

        if ("any".equals(s)) {
            return new SnortPortAny(isNot);
        }

        s = s.replaceAll("\\$FILE_DATA_PORTS", "123");
        s = s.replaceAll("\\$HTTP_PORTS", "234");
        s = s.replaceAll("\\$HTTPS_PORTS", "345");
        s = s.replaceAll("\\$FTP_PORTS", "[3,4,5]");

        if (s.matches("^\\[\\d+:\\d+\\]$")) {
            String[] parts = s.substring(1, s.length() - 2).split(":");
            try {
                int start = Integer.parseInt(parts[0]);
                int end = Integer.parseInt(parts[1]);
                return new SnortPortRange(start, end, isNot);
            } catch (NumberFormatException e) {
                throw new SnortException("Could not get port number from " + s + " in " + value);
            }
        }

        if (s.contains(":")) {
            String[] parts = s.split(":");
            try {
                int start = -1;
                if (parts[0].trim().length() > 0) {
                    start = Integer.parseInt(parts[0]);
                }
                int end = -1;
                if (parts.length > 1 && parts[1].trim().length() > 0) {
                    end = Integer.parseInt(parts[1]);
                }
                return new SnortPortRange(start, end, isNot);
            } catch (NumberFormatException e) {
                throw new SnortException("Could not get port number from " + s + " in " + value);
            }
        }

        if (s.matches("^\\[\\d+(,\\d+)+\\]$")) {
            String[] parts = s.substring(1, s.length() - 2).split(",");
            try {
                List<Integer> ports = new ArrayList<>(parts.length);
                for (String part : parts) {
                    ports.add(Integer.valueOf(part));
                }
                return new SnortPortList(ports, isNot);
            } catch (NumberFormatException e) {
                throw new SnortException("Could not get port number from " + s + " in " + value);
            }
        }

        try {
            int port = Integer.parseInt(s);
            return new SnortPortSingle(port, isNot);
        } catch (NumberFormatException e) {
// Do nothing
        }
        throw new SnortException("Unknown port syntax " + s);
    }

    public abstract boolean matches(int packetPort);
}
