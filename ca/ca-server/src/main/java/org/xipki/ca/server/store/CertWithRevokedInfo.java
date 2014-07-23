/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.store;

import org.xipki.ca.common.X509CertificateWithMetaInfo;

/**
 * @author Lijun Liao
 */

public class CertWithRevokedInfo
{
    private final X509CertificateWithMetaInfo cert;
    private final boolean revoked;

    public CertWithRevokedInfo(X509CertificateWithMetaInfo cert, boolean revoked)
    {
        this.cert = cert;
        this.revoked = revoked;
    }

    public X509CertificateWithMetaInfo getCert()
    {
        return cert;
    }

    public boolean isRevoked()
    {
        return revoked;
    }

}
