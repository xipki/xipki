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

package org.xipki.ca.cmp.client.type;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;

public class IssuerSerialEntryType extends ResultEntryType
{
    private final X500Name issuer;
    private final BigInteger serialNumber;

    public IssuerSerialEntryType(String id, X509Certificate cert)
    {
        this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()), cert.getSerialNumber());
    }

    public IssuerSerialEntryType(String id, X500Name issuer, BigInteger serialNumber)
    {
        super(id);

        this.serialNumber = serialNumber;
        this.issuer = issuer;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

}
