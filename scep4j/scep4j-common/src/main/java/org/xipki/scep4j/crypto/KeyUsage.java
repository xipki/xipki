/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.scep4j.crypto;

/**
 * @author Lijun Liao
 */

public enum KeyUsage
{
    digitalSignature  (0, org.bouncycastle.asn1.x509.KeyUsage.digitalSignature, "digitalSignature"),
    contentCommitment (1, org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation, "contentCommitment", "nonRepudiation"),
    keyEncipherment   (2, org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment, "keyEncipherment"),
    dataEncipherment  (3, org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment, "dataEncipherment"),
    keyAgreement      (4, org.bouncycastle.asn1.x509.KeyUsage.keyAgreement, "keyAgreement"),
    keyCertSign       (5, org.bouncycastle.asn1.x509.KeyUsage.keyCertSign, "keyCertSign"),
    cRLSign           (6, org.bouncycastle.asn1.x509.KeyUsage.cRLSign, "cRLSign"),
    encipherOnly      (7, org.bouncycastle.asn1.x509.KeyUsage.encipherOnly, "encipherOnly"),
    decipherOnly      (8, org.bouncycastle.asn1.x509.KeyUsage.decipherOnly, "decipherOnly");

    private int bit;
    private int bcUsage;
    private String[] names;

    private KeyUsage(
            final int bit,
            final int bcUsage,
            final String... names)
    {
        this.bit = bit;
        this.bcUsage = bcUsage;
        this.names = names;
    }

    public static KeyUsage getKeyUsage(
            final String usage)
    {
        if(usage == null)
        {
            return null;
        }

        for(KeyUsage ku : KeyUsage.values())
        {
            for(String name : ku.names)
            {
                if(name.equals(usage))
                {
                    return ku;
                }
            }
        }

        return null;
    }

    public static KeyUsage getKeyUsage(
            final int bit)
    {
        for(KeyUsage ku : KeyUsage.values())
        {
            if(ku.bit == bit)
            {
                return ku;
            }
        }

        return null;
    }

    public static KeyUsage getKeyUsageFromBcUsage(
            final int bcUsage)
    {
        for(KeyUsage ku : KeyUsage.values())
        {
            if(ku.bcUsage == bcUsage)
            {
                return ku;
            }
        }

        return null;
    }

    public int getBit()
    {
        return bit;
    }

    public int getBcUsage()
    {
        return bcUsage;
    }

    public String getName()
    {
        return names[0];
    }
}
