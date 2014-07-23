/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.store;

import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.security.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public class CertWithRevocationInfo
{
    private X509CertificateWithMetaInfo cert;
    private CertRevocationInfo revInfo;

    public CertWithRevocationInfo(X509CertificateWithMetaInfo cert, CertRevocationInfo revInfo)
    {
        this.cert = cert;
        this.revInfo = revInfo;
    }

    public X509CertificateWithMetaInfo getCert()
    {
        return cert;
    }

    public boolean isRevoked()
    {
        return revInfo != null;
    }

    public CertRevocationInfo getRevInfo()
    {
        return revInfo;
    }

    public void setCert(X509CertificateWithMetaInfo cert)
    {
        this.cert = cert;
    }

    public void setRevInfo(CertRevocationInfo revInfo)
    {
        this.revInfo = revInfo;
    }

}
