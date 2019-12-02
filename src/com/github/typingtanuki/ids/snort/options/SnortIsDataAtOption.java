package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004525000000000000000
 * <p>
 * Verify that the payload has data at a specified location, optionally looking for data relative to the end of the
 * previous content match.
 */
public class SnortIsDataAtOption extends NotImplementedSnortOption {
    public SnortIsDataAtOption(String value) {
        super(SnortOptionType.isdataat, value);
    }
}
