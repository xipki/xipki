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

import org.xipki.ocsp.api.HashAlgoType;
import org.xipki.security.common.ParamChecker;

public class IssuerHashNameAndKey {
    private final HashAlgoType algo;
    private final byte[] issuerNameHash;
    private final byte[] issuerKeyHash;

    public IssuerHashNameAndKey(HashAlgoType algo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        ParamChecker.assertNotNull("algo", algo);

        int len = algo.getLength();
        if(issuerNameHash == null || issuerNameHash.length != len)
        {
            throw new IllegalArgumentException("issuerNameash is invalid");
        }

        if(issuerKeyHash == null || issuerKeyHash.length != len)
        {
            throw new IllegalArgumentException("issuerKeyHash is invalid");
        }

        this.algo = algo;
        this.issuerNameHash = Arrays.copyOf(issuerNameHash, len);
        this.issuerKeyHash = Arrays.copyOf(issuerKeyHash, len);
    }

    public boolean match(HashAlgoType algo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        return this.algo == algo &&
                Arrays.equals(this.issuerNameHash, issuerNameHash) &&
                Arrays.equals(this.issuerKeyHash, issuerKeyHash);
    }

}
