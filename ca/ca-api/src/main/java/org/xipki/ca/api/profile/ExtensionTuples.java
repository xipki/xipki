/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Lijun Liao
 */

public class ExtensionTuples
{
    private String warning;
    private final List<ExtensionTuple> extensions = new LinkedList<>();

    public void addExtension(ExtensionTuple extension)
    {
        if(extension != null)
        {
            extensions.add(extension);
        }
    }

    public List<ExtensionTuple> getExtensions()
    {
        return Collections.unmodifiableList(extensions);
    }

    public void setWarning(String warning)
    {
        this.warning = warning;
    }

    public String getWarning()
    {
        return warning;
    }

    public boolean containsExtension(ASN1ObjectIdentifier type)
    {
        for(ExtensionTuple t : extensions)
        {
            if(t.getType().equals(type))
            {
                return true;
            }
        }
        return false;
    }

}
