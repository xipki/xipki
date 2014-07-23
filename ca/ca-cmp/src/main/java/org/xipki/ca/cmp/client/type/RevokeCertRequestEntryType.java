/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * @author Lijun Liao
 */

public class RevokeCertRequestEntryType extends IssuerSerialEntryType
{
    private final int reason;
    private final Date invalidityDate;

    public RevokeCertRequestEntryType(String id, X509Certificate cert,
            int reason, Date invalidityDate)
    {
        this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
                cert.getSerialNumber(), reason, invalidityDate);
    }

    public RevokeCertRequestEntryType(String id, X500Name issuer, BigInteger serialNumber,
            int reason, Date invalidityDate)
    {
        super(id, issuer, serialNumber);

        if((reason >= 0 && reason <= 10 && reason != 7) == false)
        {
            throw new IllegalArgumentException("invalid reason: " + reason);
        }

        this.reason = reason;
        this.invalidityDate = invalidityDate;
    }

    public int getReason()
    {
        return reason;
    }

    public Date getInvalidityDate()
    {
        return invalidityDate;
    }

}
