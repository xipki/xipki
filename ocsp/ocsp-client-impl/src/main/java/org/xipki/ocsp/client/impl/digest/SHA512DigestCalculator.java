/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.impl.digest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * @author Lijun Liao
 */

public class SHA512DigestCalculator extends AbstractDigestCalculator
{
    @Override
    protected ASN1ObjectIdentifier getObjectIdentifier()
    {
        return NISTObjectIdentifiers.id_sha512;
    }

    @Override
    protected Digest getDigester()
    {
        return new SHA512Digest();
    }
}
