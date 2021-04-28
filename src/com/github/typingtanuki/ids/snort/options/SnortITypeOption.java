package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketInfo;
import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.snort.ParserUtils;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import com.github.typingtanuki.ids.utils.PeakableIterator;

import static com.github.typingtanuki.ids.snort.ParserUtils.minMaxParser;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION004614000000000000000
 * <p>
 * The itype keyword is used to check for a specific ICMP type value.
 */
public class SnortITypeOption extends SnortOption {
    private final ParserUtils.MinMaxValue minMax;

    protected SnortITypeOption(String value) throws SnortException {
        super(SnortOptionType.itype, value);

        minMax = minMaxParser(value);
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws SnortException {
        if (packetInfo.protocol() != SnortProtocol.icmp) {
            return false;
        }
        try {
            return minMax.match(packetInfo.getIcmpType());
        } catch (OperationNotSupportedException e) {
            throw new SnortException("Error matching ICMP type", e);
        }
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
