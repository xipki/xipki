/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import java.security.cert.X509CRL;

/**
 * @author Lijun Liao
 */

public class CRLResultType implements CmpResultType
{
    private X509CRL crl;

    public CRLResultType()
    {
    }

    public void setCRL(X509CRL crl)
    {
        this.crl = crl;
    }

    public X509CRL getCRL()
    {
        return crl;
    }
}
