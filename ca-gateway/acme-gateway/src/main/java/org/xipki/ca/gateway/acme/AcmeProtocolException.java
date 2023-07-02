/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2016 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.xipki.ca.gateway.acme;

/**
 * A runtime exception that is thrown when the response of the server is violating the
 * RFC, and could not be handled or parsed for that reason. It is an indicator that the CA
 * does not fully comply with the RFC, and is usually not expected to be thrown.
 */
public class AcmeProtocolException extends RuntimeException {
    private static final long serialVersionUID = 2031203835755725193L;

    /**
     * Creates a new {@link AcmeProtocolException}.
     *
     * @param msg
     *            Reason of the exception
     */
    public AcmeProtocolException(String msg) {
        super(msg);
    }

    /**
     * Creates a new {@link AcmeProtocolException}.
     *
     * @param msg
     *            Reason of the exception
     * @param cause
     *            Cause
     */
    public AcmeProtocolException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
