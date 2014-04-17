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

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.common.ParamChecker;

public class RDNOccurrence
{
    private final int minOccurs;
    private final int maxOccurs;
    private final ASN1ObjectIdentifier type;

    public RDNOccurrence(ASN1ObjectIdentifier type)
    {
        this(type, 1, 1);
    }

    public int getMinOccurs()
    {
        return minOccurs;
    }

    public int getMaxOccurs()
    {
        return maxOccurs;
    }

    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    public RDNOccurrence(ASN1ObjectIdentifier type, int minOccurs, int maxOccurs)
    {
        ParamChecker.assertNotNull("type", type);
        if(minOccurs < 0 || maxOccurs < 0 || minOccurs > maxOccurs)
        {
            throw new IllegalArgumentException("illegal minOccurs=" + minOccurs + ", maxOccurs=" + maxOccurs);
        }
        this.type = type;
        this.minOccurs = minOccurs;
        this.maxOccurs = maxOccurs;
    }

}
