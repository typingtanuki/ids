package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.PeakableIterator;

public class NotImplementedSnortOption extends SnortOption {
    protected NotImplementedSnortOption(SnortOptionType type, String value) {
        super(type, value);
    }

    @Override
    public final boolean match(PacketMetadata metadata, PeakableIterator<SnortOption> iter) {
        System.out.println("Not implemented "+this);
        return true;
    }

    @Override
    public String toString() {
        return "{" +
                "type=" + type +
                ", value='" + value + '\'' +
                '}';
    }
}
