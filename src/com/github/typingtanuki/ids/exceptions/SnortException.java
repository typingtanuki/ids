package com.github.typingtanuki.ids.exceptions;

public class SnortException extends Exception {
    public SnortException(String message) {
        super(message);
    }

    public SnortException(String message, Throwable cause) {
        super(message, cause);
    }
}
