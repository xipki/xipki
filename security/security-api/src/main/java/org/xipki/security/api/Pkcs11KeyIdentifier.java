/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

/**
 * @author Lijun Liao
 */

public class Pkcs11KeyIdentifier implements Comparable<Pkcs11KeyIdentifier>
{
    private final byte[] keyId;
    private final String keyIdHex;
    private final String keyLabel;

    public Pkcs11KeyIdentifier(byte[] keyId, String keyLabel)
    {
        if(keyId == null && keyLabel == null)
        {
            throw new IllegalArgumentException("at least one of keyId an keyLabel must be non-null");
        }
        this.keyId = keyId;
        this.keyIdHex = (keyId == null) ? null : new String(Hex.encode(keyId)).toUpperCase();
        this.keyLabel = keyLabel;
    }

    public Pkcs11KeyIdentifier(byte[] keyId)
    {
        if(keyId == null)
        {
            throw new IllegalArgumentException("keyId could not be null");
        }
        this.keyId = keyId;
        this.keyIdHex = new String(Hex.encode(keyId)).toUpperCase();
        this.keyLabel = null;
    }

    public Pkcs11KeyIdentifier(String keyLabel)
    {
        if(keyLabel == null)
        {
            throw new IllegalArgumentException("keyLabel could not be null");
        }
        this.keyId = null;
        this.keyIdHex = null;
        this.keyLabel = keyLabel;
    }

    public byte[] getKeyId()
    {
        return keyId;
    }

    public String getKeyIdHex()
    {
        return keyIdHex;
    }

    public String getKeyLabel()
    {
        return keyLabel;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        if(keyIdHex != null)
        {
            sb.append("key-id: ").append(keyIdHex);
            if(keyLabel != null)
            {
                sb.append(", ");
            }
        }
        if(keyLabel != null)
        {
            sb.append("key-label: ").append(keyLabel);
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o)
    {
        if(this == o)
        {
            return true;
        }

        if(o instanceof Pkcs11KeyIdentifier == false)
        {
            return false;
        }

        Pkcs11KeyIdentifier o2 = (Pkcs11KeyIdentifier) o;
        if(keyId != null && o2.keyId != null)
        {
            return Arrays.equals(keyId, o2.keyId);
        }
        if(keyLabel != null && o2.keyLabel != null)
        {
            return keyLabel.equals(o2.keyLabel);
        }
        return false;
    }

    @Override
    public int compareTo(Pkcs11KeyIdentifier o)
    {
        if(this == o)
        {
            return 0;
        }

        if(keyLabel == null)
        {
            return (o.keyLabel == null) ? 0 : 1;
        }
        else
        {
            return (o.keyLabel == null) ? -1 : keyLabel.compareTo(o.keyLabel);
        }
    }

}
