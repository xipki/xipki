/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp;

import java.util.Arrays;

import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IssuerHashNameAndKey
{
    private final HashAlgoType algo;
    private final byte[] issuerNameHash;
    private final byte[] issuerKeyHash;

    public IssuerHashNameAndKey(HashAlgoType algo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        ParamChecker.assertNotNull("algo", algo);

        int len = algo.getLength();
        if(issuerNameHash == null || issuerNameHash.length != len)
        {
            throw new IllegalArgumentException("issuerNameash is invalid");
        }

        if(issuerKeyHash == null || issuerKeyHash.length != len)
        {
            throw new IllegalArgumentException("issuerKeyHash is invalid");
        }

        this.algo = algo;
        this.issuerNameHash = Arrays.copyOf(issuerNameHash, len);
        this.issuerKeyHash = Arrays.copyOf(issuerKeyHash, len);
    }

    public boolean match(HashAlgoType algo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        return this.algo == algo &&
                Arrays.equals(this.issuerNameHash, issuerNameHash) &&
                Arrays.equals(this.issuerKeyHash, issuerKeyHash);
    }

}
