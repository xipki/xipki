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
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;

public class RevokeCertRequestEntryType extends IssuerSerialEntryType
{
    private final int reason;
    private final Date invalidityDate;

    public RevokeCertRequestEntryType(String id, X509Certificate cert,
            int reason, Date invalidityDate)
    {
        this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()), cert.getSerialNumber(),
                reason, invalidityDate);
    }

    public RevokeCertRequestEntryType(String id, X500Name issuer, BigInteger serialNumber,
            int reason, Date invalidityDate)
    {
        super(id, issuer, serialNumber);

        if((reason >= 0 && reason <= 10 && reason != 7) == false)
        {
            throw new IllegalArgumentException("invalid reason: " + reason);
        }

        this.reason = reason;
        this.invalidityDate = invalidityDate;
    }

    public int getReason()
    {
        return reason;
    }

    public Date getInvalidityDate()
    {
        return invalidityDate;
    }

}
