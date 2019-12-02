package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.PeakableIterator;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00455000000000000000
 * <p>
 * The nocase keyword allows the rule writer to specify that the Snort should look for the specific pattern,
 * ignoring case. nocase modifies the previous content keyword in the rule.
 */
public class SnortNoCaseOption extends SnortOption {
    public SnortNoCaseOption(String value) {
        super(SnortOptionType.nocase, value);
    }

    @Override
    public boolean match(PacketMetadata metadata, PeakableIterator<SnortOption> iter) {
        return true;
    }
}
