package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION004610000000000000000
 * <p>
 * The flowbits keyword is used in conjunction with conversation tracking from the Session preprocessor (see Section[*]).
 * It allows rules to track states during a transport protocol session. The flowbits option is most useful for TCP
 * sessions, as it allows rules to generically track the state of an application protocol.
 */
public class SnortFlowbitsOption extends NotImplementedSnortOption {
    public SnortFlowbitsOption(String value) {
        super(SnortOptionType.flowbits, value);
    }
}
