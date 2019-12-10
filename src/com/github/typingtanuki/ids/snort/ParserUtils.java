package com.github.typingtanuki.ids.snort;

import com.github.typingtanuki.ids.exceptions.SnortException;

public final class ParserUtils {
    private ParserUtils() {
    }

    public static MinMaxValue minMaxParser(String toParse) throws SnortException {
        if (toParse.contains("<>")) {
            String[] parts = toParse.split("<>");
            if (parts.length != 2) {
                throw new SnortException("Could not parse <> syntax from " + toParse);
            }
            return new MinMaxValue(intFrom(parts[0]), intFrom(parts[1]));
        }
        assertNotEmpty(toParse);
        char prefix = toParse.charAt(0);
        switch (prefix) {
            case '>':
                return new MinMaxValue(intFrom(toParse.substring(1)), null);
            case '<':
                return new MinMaxValue(null, intFrom(toParse.substring(1)));
        }
        int i = intFrom(toParse);
        return new MinMaxValue(i, i);
    }

    private static void assertNotEmpty(String value) throws SnortException {
        if (value.isBlank()) {
            throw new SnortException("Nothing to parse");
        }
    }

    private static Integer intFrom(String s) throws SnortException {
        assertNotEmpty(s);
        try {
            return Integer.valueOf(s);
        } catch (NumberFormatException e) {
            throw new SnortException("Could not parse number from " + s, e);
        }
    }

    public static class MinMaxValue {
        private final Integer min;
        private final Integer max;

        public MinMaxValue(Integer min, Integer max) {
            this.min = min;
            this.max = max;
        }

        public Integer getMin() {
            return min;
        }

        public Integer getMax() {
            return max;
        }

        public boolean match(int target) {
            if (min != null && target < min) {
                return false;
            }
            if (max != null && target > max) {
                return false;
            }
            return true;
        }
    }
}
