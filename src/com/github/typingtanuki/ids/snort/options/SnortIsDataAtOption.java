package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.utils.PeakableIterator;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004525000000000000000
 * <p>
 * Verify that the payload has data at a specified location, optionally looking for data relative to the end of the
 * previous content match.
 */
public class SnortIsDataAtOption extends SnortOption {
    private boolean isNot;
    private int position;
    private SnortPositionType positioning;

    public SnortIsDataAtOption(String value) throws SnortException {
        super(SnortOptionType.isdataat, value);

        parseValue(value);
    }

    private void parseValue(String value) throws SnortException {
        String s = value;
        isNot = false;
        if (s.startsWith("!")) {
            isNot = true;
            s = s.substring(1);
        }
        String[] parts = s.split(",");
        if (parts.length > 2 || parts.length < 1) {
            throw new SnortException("Invalid isdataat, expected 1 or 2 elements, got " + s + " for " + value);
        }
        try {
            position = Integer.parseInt(parts[0]);
        } catch (NumberFormatException e) {
            throw new SnortException("Invalid isdataat, expected position, got " + parts[0] + " for " + value, e);
        }
        if (parts.length == 2) {
            try {
                positioning = SnortPositionType.valueOf(parts[1]);
            } catch (IllegalArgumentException e) {
                throw new SnortException("Invalid isdataat, expected position type, got " + parts[1] + " for " + value, e);
            }
        } else {
            positioning = SnortPositionType.absolute;
        }
    }

    @Override
    public boolean match(PacketMetadata metadata) throws SnortException {
        boolean match;
        switch (positioning) {
            case absolute:
                match = absoluteMatch(metadata);
                break;
            case relative:
                match = relativeMatch(metadata);
                break;
            default:
                throw new SnortException("Unsupported positioning type " + positioning);
        }
        if (isNot) {
            return !match;
        }
        return match;
    }

    private boolean relativeMatch(PacketMetadata metadata) {
        int length = metadata.payload().length;
        return length <= position + metadata.getPointerPos();
    }

    private boolean absoluteMatch(PacketMetadata metadata) {
        int length = metadata.payload().length;
        return length <= position;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) throws SnortException {

    }
}
