package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION00467000000000000000
 * <p>
 * The dsize keyword is used to test the packet payload size. This may be used to check for abnormally sized packets
 * that might cause buffer overflows.
 */
public class SnortDSizeOption extends NotImplementedSnortOption {
    public SnortDSizeOption(String value) {
        super(SnortOptionType.dsize, value);
    }
}
