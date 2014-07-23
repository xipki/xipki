/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class Pkcs12_SHA256withRSA_Test extends Pkcs12_RSA_Test
{
    @Override
    protected ASN1ObjectIdentifier getSignatureAlgorithm()
    {
        return PKCSObjectIdentifiers.sha256WithRSAEncryption;
    }

}
