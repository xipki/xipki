/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.Collections;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Lijun Liao
 */

class GeneralNameMode
{
    private final GeneralNameTag tag;
    // not applied to all tags, currently only for tag otherName
    private final Set<ASN1ObjectIdentifier> allowedTypes;

    public GeneralNameMode(GeneralNameTag tag)
    {
        this.tag = tag;
        this.allowedTypes = null;
    }

    public GeneralNameMode(GeneralNameTag tag, Set<ASN1ObjectIdentifier> allowedTypes)
    {
        this.tag = tag;
        this.allowedTypes = allowedTypes == null ? null : Collections.unmodifiableSet(allowedTypes);
    }

    public GeneralNameTag getTag()
    {
        return tag;
    }

    public Set<ASN1ObjectIdentifier> getAllowedTypes()
    {
        return allowedTypes;
    }

}
