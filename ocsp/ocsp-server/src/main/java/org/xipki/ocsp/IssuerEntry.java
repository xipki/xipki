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

package org.xipki.ocsp;

import java.util.Arrays;
import java.util.Map;

import org.xipki.ocsp.api.HashAlgoType;

public class IssuerEntry
{
    private final int id;
    private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap;
    private final byte[] encodedCert;

    public IssuerEntry(int id, Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap,
            byte[] encodedCert)
    {
        if(issuerHashMap == null || issuerHashMap.isEmpty())
        {
            throw new IllegalArgumentException("issuerHashMap is empty");
        }

        this.id = id;
        this.issuerHashMap = issuerHashMap;
        this.encodedCert = encodedCert;
    }

    public int getId() {
        return id;
    }

    public boolean matchCert(byte[] encodedCert)
    {
        if(encodedCert == null)
        {
            return false;
        }

        return Arrays.equals(this.encodedCert, encodedCert);
    }

    public boolean matchHash(HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        IssuerHashNameAndKey issuerHash = issuerHashMap.get(hashAlgo);
        return issuerHash == null ? false : issuerHash.match(hashAlgo, issuerNameHash, issuerKeyHash);
    }
}
