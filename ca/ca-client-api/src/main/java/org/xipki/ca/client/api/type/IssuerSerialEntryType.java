/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api.type;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * @author Lijun Liao
 */

public class IssuerSerialEntryType extends ResultEntryType
{
    private final X500Name issuer;
    private final BigInteger serialNumber;

    public IssuerSerialEntryType(String id, X509Certificate cert)
    {
        this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()), cert.getSerialNumber());
    }

    public IssuerSerialEntryType(String id, X500Name issuer, BigInteger serialNumber)
    {
        super(id);

        this.serialNumber = serialNumber;
        this.issuer = issuer;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

}
