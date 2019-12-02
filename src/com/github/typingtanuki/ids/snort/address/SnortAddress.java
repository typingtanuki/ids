package com.github.typingtanuki.ids.snort.address;

import com.github.typingtanuki.ids.snort.SnortException;

import java.net.InetAddress;

public abstract class SnortAddress {
    public static SnortAddress of(String value) throws SnortException {
        String s = value;
        boolean isNot = false;
        if (s.startsWith("!")) {
            isNot = true;
            s = s.substring(1);
        }

        if ("any".equals(s)) {
            return new SnortAddressAny(isNot);
        }
        if (s.contains("/")) {
            String[] parts = s.split("/", 2);
            if (!parts[0].matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(\\.\\d{1,3})?$")) {
                throw new SnortException("Invalid IP address " + parts[0] + " in " + value);
            }
            try {
                int mask = Integer.parseInt(parts[1]);
                String ip = parts[0];
                while (ip.split("\\.").length < 4) {
                    ip = ip + ".0";
                }
                return new SnortAddressNetwork(ip, mask, isNot);
            } catch (NumberFormatException e) {
                throw new SnortException("Invalid IP mask " + parts[1] + " in " + value, e);
            }
        }
        if (s.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return new SnortAddressIpV4(s, isNot);
        }
        if ("$HOME_NET".equals(s)) {
            return new SnortAddressNetwork("192.168.0.00", 24, isNot);
        }
        if ("$EXTERNAL_NET".equals(s)) {
            return new SnortAddressNetwork("192.168.0.00", 24, !isNot);
        }
        if ("$SMTP_SERVERS".equals(s)) {
            return new SnortAddressNetwork("192.168.10.0", 24, !isNot);
        }
        if ("$HTTP_SERVERS".equals(s)) {
            return new SnortAddressNetwork("192.168.11.0", 24, !isNot);
        }
        if ("$TELNET_SERVERS".equals(s)) {
            return new SnortAddressNetwork("192.168.12.0", 24, !isNot);
        }
        throw new SnortException("Unknown address syntax " + s);
    }

    public abstract boolean matches(InetAddress packetAddr) throws SnortException;
}
