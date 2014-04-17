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

package org.xipki.ocsp.api;

public enum HashAlgoType
{
    SHA1  (20, "1.3.14.3.2.26", "SHA1"),
    SHA224(28, "2.16.840.1.101.3.4.2.4", "SHA224"),
    SHA256(32, "2.16.840.1.101.3.4.2.1", "SHA256"),
    SHA384(48, "2.16.840.1.101.3.4.2.2", "SHA384"),
    SHA512(64, "2.16.840.1.101.3.4.2.3", "SHA512");

    private final int length;
    private final String oid;
    private final String name;

    private HashAlgoType(int length, String oid, String name)
    {
        this.length = length;
        this.oid = oid;
        this.name = name;
    }

    public int getLength()
    {
        return length;
    }

    public String getOid()
    {
        return oid;
    }

    public String getName()
    {
        return name;
    }

    public static HashAlgoType getHashAlgoType(String nameOrOid)
    {
        for(HashAlgoType hashAlgo : values())
        {
            if(hashAlgo.oid.equals(nameOrOid))
            {
                return hashAlgo;
            }

            if(nameOrOid.indexOf('-') != -1)
            {
                nameOrOid = nameOrOid.replace("-", "");
            }

            if(hashAlgo.name.equalsIgnoreCase(nameOrOid))
            {
                return hashAlgo;
            }
        }

        return null;
    }
}
