package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketInfo;
import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.utils.PeakableIterator;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION00469000000000000000
 * <p>
 * The flow keyword is used in conjunction with session tracking (see Section [*]). It allows rules to only apply to
 * certain directions of the traffic flow.
 */
public class SnortFlowOption extends SnortOption {
    private boolean established = false;
    private boolean toServer = false;
    private boolean fromServer = false;

    public SnortFlowOption(String value) {
        super(SnortOptionType.flow, value);
        parseValue(value);
    }

    private void parseValue(String value) {
        String[] parts = value.split(",");
        for (String part : parts) {
            if (part.equalsIgnoreCase("established")) {
                established = true;
            } else if (part.equalsIgnoreCase("to_server")) {
                toServer = true;
            } else if (part.equalsIgnoreCase("from_server")) {
                fromServer = true;
            }
        }
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws SnortException {
        try {
            if (established && !packetInfo.getFlowManager().isEstablished(packetInfo)) {
                return false;
            }
            if (fromServer && !packetInfo.getFlowManager().isFromServer(packetInfo)) {
                return false;
            }
            if (toServer && packetInfo.getFlowManager().isFromServer(packetInfo)) {
                return false;
            }
        } catch (OperationNotSupportedException e) {
            throw new SnortException("Could not check flow of packet", e);
        }
        return true;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        //Nothing to do
    }
}
