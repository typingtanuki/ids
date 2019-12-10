package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketInfo;
import com.github.typingtanuki.ids.snort.ParserUtils;
import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.utils.PeakableIterator;

import static com.github.typingtanuki.ids.snort.ParserUtils.minMaxParser;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION00467000000000000000
 * <p>
 * The dsize keyword is used to test the packet payload size. This may be used to check for abnormally sized packets
 * that might cause buffer overflows.
 */
public class SnortDSizeOption extends SnortOption {
    private final ParserUtils.MinMaxValue minMax;

    public SnortDSizeOption(String value) throws SnortException {
        super(SnortOptionType.dsize, value);

        minMax = minMaxParser(value);
    }

    @Override
    public boolean match(PacketInfo packetInfo) {
        return minMax.match(packetInfo.payload().length);
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
