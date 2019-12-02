package com.github.typingtanuki.ids.snort.options;

public class NotClassedSnortOption extends NotImplementedSnortOption {
    public NotClassedSnortOption(SnortOptionType type, String value) {
        super(type, value);
        System.out.println("Snort option without class: " + this);
    }
}
