/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp;

import java.util.Date;
import java.util.Map;

import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IssuerEntry
{
    private final int id;
    private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap;
    private final Date caNotBefore;

    private boolean revoked;
    private Date revocationTime;

    public IssuerEntry(int id, Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap, Date caNotBefore)
    {
        ParamChecker.assertNotEmpty("issuerHashMap", issuerHashMap);
        ParamChecker.assertNotNull("caNotBefore", caNotBefore);

        this.id = id;
        this.issuerHashMap = issuerHashMap;
        this.caNotBefore = caNotBefore;
    }

    public int getId()
    {
        return id;
    }

    public boolean matchHash(HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        IssuerHashNameAndKey issuerHash = issuerHashMap.get(hashAlgo);
        return issuerHash == null ? false : issuerHash.match(hashAlgo, issuerNameHash, issuerKeyHash);
    }

    public boolean isRevoked()
    {
        return revoked;
    }

    public void setRevoked(boolean revoked)
    {
        this.revoked = revoked;
    }

    public Date getRevocationTime()
    {
        return revocationTime;
    }

    public void setRevocationTime(Date revocationTime)
    {
        this.revocationTime = revocationTime;
    }

    public Date getCaNotBefore()
    {
        return caNotBefore;
    }
}
