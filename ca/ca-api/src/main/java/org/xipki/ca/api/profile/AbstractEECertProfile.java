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

public abstract class AbstractEECertProfile extends AbstractCertProfile
{
    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return ExtensionOccurrence.NONCRITICAL_REQUIRED;
    }

    @Override
    protected boolean isCa()
    {
        return false;
    }

    @Override
    protected Integer getPathLenBasicConstraint()
    {
        return null;
    }

}
