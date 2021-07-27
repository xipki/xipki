package org.xipki.util;

public class OpRuntimeException extends RuntimeException {

    public OpRuntimeException() {
    }

    public OpRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public OpRuntimeException(String message) {
        super(message);
    }

    public OpRuntimeException(Throwable cause) {
        super(cause.getMessage(), cause);
    }

}