package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketInfo;
import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.utils.PeakableIterator;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004525000000000000000
 * <p>
 * Verify that the payload has data at a specified location, optionally looking for data relative to the end of the
 * previous content match.
 */
public class SnortIsDataAtOption extends SnortOption {
    private boolean isNot;
    private DataPosition position;

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

        SnortPositionType positioning;
        if (parts.length == 2) {
            try {
                positioning = SnortPositionType.valueOf(parts[1]);
            } catch (IllegalArgumentException e) {
                throw new SnortException("Invalid isdataat, expected position type, got " + parts[1] + " for " + value, e);
            }
        } else {
            positioning = SnortPositionType.absolute;
        }

        if ("file_length".equalsIgnoreCase(parts[0])) {
            position = new DataPosition(DataPositionType.fileLength, null, positioning);
        } else if ("data_length".equalsIgnoreCase(parts[0])) {
            position = new DataPosition(DataPositionType.dataLength, null, positioning);
        } else if ("length".equalsIgnoreCase(parts[0])) {
            position = new DataPosition(DataPositionType.length, null, positioning);
        } else if ("SftOffset".equalsIgnoreCase(parts[0])) {
            position = new DataPosition(DataPositionType.sftOffset, null, positioning);
        } else {
            try {
                position = new DataPosition(DataPositionType.bytes, Long.parseLong(parts[0]), positioning);
            } catch (NumberFormatException e) {
                throw new SnortException("Invalid isdataat, expected position, got " + parts[0] + " for " + value, e);
            }
        }
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws SnortException {
        boolean match;
        switch (position.getPositioning()) {
            case absolute:
                match = absoluteMatch(packetInfo);
                break;
            case relative:
                match = relativeMatch(packetInfo);
                break;
            default:
                throw new SnortException("Unsupported positioning type " + position.getPositioning());
        }
        if (isNot) {
            return !match;
        }
        return match;
    }

    private boolean relativeMatch(PacketInfo packetInfo) {
        int length = packetInfo.payload().length;
        return length <= position.getOffest() + packetInfo.getPointerPos();
    }

    private boolean absoluteMatch(PacketInfo packetInfo) {
        int length = packetInfo.payload().length;
        return length <= position.getOffest();
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {

    }
}
