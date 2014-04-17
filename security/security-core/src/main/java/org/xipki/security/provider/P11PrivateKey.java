/*
 * Copyright 2014 xipki.org
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

package org.xipki.security.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;

public class P11PrivateKey implements PrivateKey {

    private static final long serialVersionUID = 1L;

    private final P11CryptService p11CryptService;
    private final PKCS11SlotIdentifier slotId;
    private final Pkcs11KeyIdentifier keyId;
    private final String algorithm;
    private final int keysize;


    public P11PrivateKey(P11CryptService p11CryptService, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId) throws InvalidKeyException
    {
        if(p11CryptService == null)
        {
            throw new IllegalArgumentException("p11CryptService could not be null");
        }
        if(slotId == null)
        {
            throw new IllegalArgumentException("slotId could not be null");
        }
        if(keyId == null)
        {
            throw new IllegalArgumentException("keyId could not be null");
        }

        this.p11CryptService = p11CryptService;
        this.slotId = slotId;
        this.keyId = keyId;
        PublicKey publicKey;
        try {
            publicKey = p11CryptService.getPublicKey(slotId, keyId);
        } catch (SignerException e) {
            throw new InvalidKeyException(e);
        }

        if(publicKey instanceof RSAPublicKey)
        {
            algorithm = "RSA";
            keysize = ((RSAPublicKey) publicKey).getModulus().bitLength();
        }
        else if(publicKey instanceof ECPublicKey)
        {
            algorithm = "EC";
            keysize = ((ECPublicKey) publicKey).getParams().getCurve().getField().getFieldSize();
        }
        else
        {
            throw new InvalidKeyException("Unknown public key: " + publicKey);
        }
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    public int getKeysize() {
        return keysize;
    }

    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo) throws SignatureException
    {
        if("RSA".equals(algorithm) == false)
        {
            throw new SignatureException("Could not compute RSA signature with " + algorithm + " key");
        }

        try {
            return p11CryptService.CKM_RSA_PKCS(encodedDigestInfo, slotId, keyId);
        } catch (SignerException e) {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_RSA_X509(byte[] hash) throws SignatureException
    {
        if("RSA".equals(algorithm) == false)
        {
            throw new SignatureException("Could not compute RSA signature with " + algorithm + " key");
        }

        try {
            return p11CryptService.CKM_RSA_X509(hash, slotId, keyId);
        } catch (SignerException e) {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    public byte[] CKM_ECDSA(byte[] hash) throws SignatureException
    {
        if("EC".equals(algorithm) == false)
        {
            throw new SignatureException("Could not compute ECDSA signature with " + algorithm + " key");
        }

        try {
            return p11CryptService.CKM_ECDSA(hash, slotId, keyId);
        } catch (SignerException e) {
            throw new SignatureException("SignatureException: " + e.getMessage(), e);
        }
    }

    P11CryptService getP11CryptService() {
        return p11CryptService;
    }

    PKCS11SlotIdentifier getSlotId() {
        return slotId;
    }

    Pkcs11KeyIdentifier getKeyId() {
        return keyId;
    }




}
