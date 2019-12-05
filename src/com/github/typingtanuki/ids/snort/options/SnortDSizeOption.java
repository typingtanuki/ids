package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.PeakableIterator;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION00467000000000000000
 * <p>
 * The dsize keyword is used to test the packet payload size. This may be used to check for abnormally sized packets
 * that might cause buffer overflows.
 */
public class SnortDSizeOption extends SnortOption {
    private int min = -1;
    private int max = Integer.MAX_VALUE;

    public SnortDSizeOption(String value) {
        super(SnortOptionType.dsize, value);
        boolean isMax = true;
        if (value.charAt(0) == '<') {
            isMax = true;
            value = value.substring(1);
        } else if (value.charAt(0) == '>') {
            isMax = false;
            value = value.substring(1);
        }

        int extracted = Integer.parseInt(value);
        if (isMax) {
            max = extracted;
        } else {
            min = extracted;
        }
    }

    @Override
    public boolean match(PacketMetadata metadata) {
        return metadata.getData().length <= min || metadata.getData().length >= max;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
