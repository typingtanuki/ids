package com.github.typingtanuki.ids.snort;

public class SnortException extends Exception {
    public SnortException(String message) {
        super(message);
    }

    public SnortException(String message, Throwable cause) {
        super(message, cause);
    }
}
