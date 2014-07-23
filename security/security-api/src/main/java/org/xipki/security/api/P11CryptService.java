/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author Lijun Liao
 */

public interface P11CryptService
{
    public void refresh()
    throws SignerException;

    byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException;

    byte[] CKM_RSA_X509(byte[] hash, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException;

    byte[] CKM_ECDSA(byte[] hash, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException;

    PublicKey getPublicKey(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException;

    X509Certificate getCertificate(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException;

    X509Certificate[] getCertificates(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException;

    PKCS11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException;

    String[] getKeyLabels(PKCS11SlotIdentifier slotId)
    throws SignerException;
}
