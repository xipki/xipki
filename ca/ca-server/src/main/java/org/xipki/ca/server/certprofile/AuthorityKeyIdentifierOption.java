/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import org.xipki.ca.api.profile.ExtensionOccurrence;

/**
 * @author Lijun Liao
 */

class AuthorityKeyIdentifierOption
{
    private final boolean includeIssuerAndSerial;
    private final boolean absentIfSelfSigned;
    private final ExtensionOccurrence occurence;

    AuthorityKeyIdentifierOption(boolean includeIssuerAndSerial,
            boolean absentIfSelfSigned,
            ExtensionOccurrence occurence)
    {
        this.includeIssuerAndSerial = includeIssuerAndSerial;
        this.absentIfSelfSigned = absentIfSelfSigned;
        this.occurence = occurence;
    }

    boolean isIncludeIssuerAndSerial()
    {
        return includeIssuerAndSerial;
    }

    ExtensionOccurrence getOccurence(boolean selfSigned)
    {
        if(selfSigned)
        {
            return absentIfSelfSigned ? null : occurence;
        }
        else
        {
            return occurence;
        }
    }

}
