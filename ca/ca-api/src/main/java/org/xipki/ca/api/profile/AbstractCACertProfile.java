/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public abstract class AbstractCACertProfile extends AbstractCertProfile
{
    protected Set<KeyUsage> keyUsages;

    public AbstractCACertProfile()
    {
        Set<KeyUsage> keyUsages = new HashSet<>();
        keyUsages.add(KeyUsage.keyCertSign);
        keyUsages.add(KeyUsage.cRLSign);
        this.keyUsages = Collections.unmodifiableSet(keyUsages);
    }

    @Override
    protected boolean isCa()
    {
        return true;
    }

    @Override
    protected Set<KeyUsage> getKeyUsage()
    {
        return keyUsages;
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return ExtensionOccurrence.NONCRITICAL_REQUIRED;
    }
}
