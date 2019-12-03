package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.PeakableIterator;

public class NotImplementedSnortOption extends SnortOption {
    protected NotImplementedSnortOption(SnortOptionType type, String value) {
        super(type, value);
    }

    @Override
    public final boolean match(PacketMetadata metadata) {
        System.out.println("Not implemented "+this);
        return true;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }

    @Override
    public String toString() {
        return "{" +
                "type=" + type +
                ", value='" + value + '\'' +
                '}';
    }
}
