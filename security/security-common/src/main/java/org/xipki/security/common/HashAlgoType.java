/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.common;

/**
 * @author Lijun Liao
 */

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
