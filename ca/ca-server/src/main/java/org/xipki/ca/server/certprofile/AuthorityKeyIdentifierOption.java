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
    private final ExtensionOccurrence occurence;

    AuthorityKeyIdentifierOption(boolean includeIssuerAndSerial,
            ExtensionOccurrence occurence)
    {
        this.includeIssuerAndSerial = includeIssuerAndSerial;
        this.occurence = occurence;
    }

    boolean isIncludeIssuerAndSerial()
    {
        return includeIssuerAndSerial;
    }

    ExtensionOccurrence getOccurence()
    {
        return occurence;
    }

}
