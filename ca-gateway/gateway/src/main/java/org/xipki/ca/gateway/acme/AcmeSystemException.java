// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeSystemException extends Exception {

    public AcmeSystemException(String msg) {
        super(msg);
    }

    public AcmeSystemException(Throwable cause) {
        super(cause);
    }

    public AcmeSystemException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
