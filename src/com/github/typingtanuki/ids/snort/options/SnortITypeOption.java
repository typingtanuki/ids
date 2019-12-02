package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION004614000000000000000
 * <p>
 * The itype keyword is used to check for a specific ICMP type value.
 */
public class SnortITypeOption extends NotImplementedSnortOption {
    protected SnortITypeOption(String value) {
        super(SnortOptionType.itype, value);
    }
}
