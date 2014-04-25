/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.api;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

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
