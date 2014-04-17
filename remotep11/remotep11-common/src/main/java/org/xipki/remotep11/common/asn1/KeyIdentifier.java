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

package org.xipki.remotep11.common.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.security.api.Pkcs11KeyIdentifier;

/**
 *
 * <pre>
 * SlotIdentifier ::= CHOICE
 {
 *     keyLabel   UTF8STRING,
 *     keyId      OCTET STRING
 * }
 * </pre>
 *
 */

public class KeyIdentifier extends ASN1Object
{
    private Pkcs11KeyIdentifier keyId;

    public KeyIdentifier(Pkcs11KeyIdentifier keyId)
    {
        if(keyId == null)
        {
            throw new IllegalArgumentException("keyId could not be null");
        }

        this.keyId = keyId;
    }

    public static KeyIdentifier getInstance(
            Object obj)
    {
        if (obj == null || obj instanceof KeyIdentifier)
        {
            return (KeyIdentifier)obj;
        }

        if (obj instanceof ASN1OctetString)
        {
            byte[] keyIdBytes = ((ASN1OctetString) obj).getOctets();
            Pkcs11KeyIdentifier keyIdentifier = new Pkcs11KeyIdentifier(keyIdBytes);
            return new KeyIdentifier(keyIdentifier);
        }
        else if(obj instanceof DERUTF8String)
        {
            String keyLabel = ((DERUTF8String) obj).getString();
            Pkcs11KeyIdentifier keyIdentifier = new Pkcs11KeyIdentifier(keyLabel);
            return new KeyIdentifier(keyIdentifier);
        }

        if (obj instanceof byte[])
        {
            try
            {
                return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("unable to parse encoded general name");
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        if (keyId.getKeyLabel() != null)
        {
            return new DERUTF8String(keyId.getKeyLabel());
        }
        else
        {
            return new DEROctetString(keyId.getKeyId());
        }
    }

    public Pkcs11KeyIdentifier getKeyId()
    {
        return keyId;
    }


}
