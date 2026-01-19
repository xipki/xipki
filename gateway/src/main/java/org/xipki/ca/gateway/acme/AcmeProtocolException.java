// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.type.AcmeError;
import org.xipki.util.codec.Args;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeProtocolException extends Exception {

    private final int httpError;

    private final AcmeError acmeError;

    private final String acmeDetail;

    public AcmeProtocolException(int httpError, AcmeError acmeError,
                                 String acmeDetail) {
        super(acmeError + ": " + acmeDetail);
        this.httpError = httpError;
        this.acmeError = Args.notNull(acmeError, "acmeError");
        this.acmeDetail = acmeDetail;
    }

    public int getHttpError() {
        return httpError;
    }

    public AcmeError getAcmeError() {
        return acmeError;
    }

    public String getAcmeDetail() {
        return acmeDetail;
    }
}
