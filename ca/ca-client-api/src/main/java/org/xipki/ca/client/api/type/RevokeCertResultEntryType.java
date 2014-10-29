/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api.type;

import org.bouncycastle.asn1.crmf.CertId;

/**
 * @author Lijun Liao
 */

public class RevokeCertResultEntryType extends ResultEntryType
{
    private final CertId certID;

    public RevokeCertResultEntryType(String id, CertId certID)
    {
        super(id);
        this.certID = certID;
    }

    public CertId getCertID()
    {
        return certID;
    }
}
