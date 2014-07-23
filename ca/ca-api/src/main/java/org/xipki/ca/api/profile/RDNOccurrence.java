/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class RDNOccurrence
{
    private final int minOccurs;
    private final int maxOccurs;
    private final ASN1ObjectIdentifier type;

    public RDNOccurrence(ASN1ObjectIdentifier type)
    {
        this(type, 1, 1);
    }

    public int getMinOccurs()
    {
        return minOccurs;
    }

    public int getMaxOccurs()
    {
        return maxOccurs;
    }

    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    public RDNOccurrence(ASN1ObjectIdentifier type, int minOccurs, int maxOccurs)
    {
        ParamChecker.assertNotNull("type", type);
        if(minOccurs < 0 || maxOccurs < 1 || minOccurs > maxOccurs)
        {
            throw new IllegalArgumentException("illegal minOccurs=" + minOccurs + ", maxOccurs=" + maxOccurs);
        }
        this.type = type;
        this.minOccurs = minOccurs;
        this.maxOccurs = maxOccurs;
    }

}
