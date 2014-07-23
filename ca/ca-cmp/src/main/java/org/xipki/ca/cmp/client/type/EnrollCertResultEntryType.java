/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIStatus;

/**
 * @author Lijun Liao
 */

public class EnrollCertResultEntryType extends ResultEntryType
{
    private final CMPCertificate cert;
    private final int status;

    public EnrollCertResultEntryType(String id, CMPCertificate cert)
    {
        this(id, cert, PKIStatus.GRANTED);
    }

    public EnrollCertResultEntryType(String id, CMPCertificate cert, int status)
    {
        super(id);
        this.cert = cert;
        this.status = status;
    }

    public CMPCertificate getCert()
    {
        return cert;
    }

    public int getStatus()
    {
        return status;
    }
}
