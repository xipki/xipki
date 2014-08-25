/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public interface P11CryptService
{
    public void refresh()
    throws SignerException;

    byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException;

    byte[] CKM_RSA_X509(byte[] hash, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException;

    byte[] CKM_ECDSA(byte[] hash, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException;

    PublicKey getPublicKey(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException;

    X509Certificate getCertificate(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException;

    X509Certificate[] getCertificates(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException;

    P11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException;

    String[] getKeyLabels(P11SlotIdentifier slotId)
    throws SignerException;
}
