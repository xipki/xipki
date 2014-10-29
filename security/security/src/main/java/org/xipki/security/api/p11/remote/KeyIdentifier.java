/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11.remote;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.security.api.p11.P11KeyIdentifier;

/**
 *
 * <pre>
 * SlotIdentifier ::= CHOICE
 * {
 *     keyLabel   UTF8STRING,
 *     keyId      OCTET STRING
 * }
 * </pre>
 *
 * @author Lijun Liao
 */

public class KeyIdentifier extends ASN1Object
{
    private P11KeyIdentifier keyId;

    public KeyIdentifier(P11KeyIdentifier keyId)
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
            P11KeyIdentifier keyIdentifier = new P11KeyIdentifier(keyIdBytes);
            return new KeyIdentifier(keyIdentifier);
        }
        else if(obj instanceof ASN1String)
        {
            String keyLabel = ((ASN1String) obj).getString();
            P11KeyIdentifier keyIdentifier = new P11KeyIdentifier(keyLabel);
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

    public P11KeyIdentifier getKeyId()
    {
        return keyId;
    }

}
