/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

/**
 * @author Lijun Liao
 */

public enum KeyUsage
{
    digitalSignature  (0, "digitalSignature"),
    contentCommitment (1, "contentCommitment", "nonRepudiation"),
    keyEncipherment   (2, "keyEncipherment"),
    dataEncipherment  (3, "dataEncipherment"),
    keyAgreement      (4, "keyAgreement"),
    keyCertSign       (5, "keyCertSign"),
    cRLSign           (6, "cRLSign"),
    encipherOnly      (7, "encipherOnly"),
    decipherOnly      (8, "decipherOnly");

    private int bit;
    private String[] names;

    private KeyUsage(int bit, String... names)
    {
        this.bit = bit;
        this.names = names;
    }

    public static KeyUsage getKeyUsage(String usage)
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

    public static KeyUsage getKeyUsage(int bit)
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
}
