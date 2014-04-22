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

package org.xipki.security.api;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

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
        this.keyIdHex = (keyId == null) ? null : Hex.toHexString(keyId).toUpperCase();
        this.keyLabel = keyLabel;
    }

    public Pkcs11KeyIdentifier(byte[] keyId)
    {
        if(keyId == null)
        {
            throw new IllegalArgumentException("keyId could not be null");
        }
        this.keyId = keyId;
        this.keyIdHex = Hex.toHexString(keyId).toUpperCase();
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
        sb.append("key-id: ").append(keyIdHex);
        sb.append(", key-label: ").append(keyLabel);
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
