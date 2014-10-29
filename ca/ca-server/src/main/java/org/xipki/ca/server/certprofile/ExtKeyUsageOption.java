/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Lijun Liao
 */

class ExtKeyUsageOption
{
    private final Condition condition;
    private final Set<ASN1ObjectIdentifier> extKeyusages;

    public ExtKeyUsageOption(Condition condition, Set<ASN1ObjectIdentifier> extKeyusages)
    {
        this.condition = condition;
        this.extKeyusages = extKeyusages;
    }

    public Condition getCondition()
    {
        return condition;
    }

    public Set<ASN1ObjectIdentifier> getExtKeyusages()
    {
        return extKeyusages;
    }

}
