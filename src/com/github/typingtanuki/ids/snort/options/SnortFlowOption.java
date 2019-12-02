package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION00469000000000000000
 * <p>
 * The flow keyword is used in conjunction with session tracking (see Section [*]). It allows rules to only apply to
 * certain directions of the traffic flow.
 */
public class SnortFlowOption extends NotImplementedSnortOption {
    public SnortFlowOption(String value) {
        super(SnortOptionType.flow, value);
    }
}
