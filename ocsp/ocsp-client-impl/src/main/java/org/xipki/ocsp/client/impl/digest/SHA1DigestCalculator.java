/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.impl.digest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * @author Lijun Liao
 */

public class SHA1DigestCalculator extends AbstractDigestCalculator
{
    @Override
    protected ASN1ObjectIdentifier getObjectIdentifier()
    {
        return OIWObjectIdentifiers.idSHA1;
    }

    @Override
    protected Digest getDigester()
    {
        return new SHA1Digest();
    }
}
