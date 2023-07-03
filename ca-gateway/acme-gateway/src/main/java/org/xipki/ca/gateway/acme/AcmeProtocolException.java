// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeProtocolException extends RuntimeException {
    private static final long serialVersionUID = 2031203835755725193L;

    public AcmeProtocolException(String msg) {
        super(msg);
    }

    public AcmeProtocolException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
