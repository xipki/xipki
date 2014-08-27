/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.xipki.security.common.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public abstract class KeyGenCommand extends SecurityCommand
{
    protected Integer getKeyUsage()
    throws Exception
    {
        return KeyUsage.cRLSign |
                KeyUsage.dataEncipherment |
                KeyUsage.digitalSignature |
                KeyUsage.keyAgreement |
                KeyUsage.keyCertSign |
                KeyUsage.keyEncipherment;
    }

    protected List<ASN1ObjectIdentifier> getExtendedKeyUsage()
    throws Exception
    {
        return Arrays.asList(ObjectIdentifiers.id_kp_clientAuth,
                ObjectIdentifiers.id_kp_serverAuth,
                ObjectIdentifiers.id_kp_emailProtection,
                ObjectIdentifiers.id_kp_OCSPSigning);
    }
}
