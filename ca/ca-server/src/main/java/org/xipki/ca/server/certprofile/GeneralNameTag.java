/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

/**
 * @author Lijun Liao
 */

enum GeneralNameTag
{
    otherName(0),
    rfc822Name(1),
    dNSName(2),
    x400Adress(3),
    directoryName(4),
    ediPartyName(5),
    uniformResourceIdentifier(6),
    iPAddress(7),
    registeredID(8);

    private final int tag;
    private GeneralNameTag(int tag)
    {
        this.tag = tag;
    }

    public int getTag()
    {
        return tag;
    }
}
