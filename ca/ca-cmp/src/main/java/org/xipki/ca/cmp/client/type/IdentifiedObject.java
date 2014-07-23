/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IdentifiedObject
{
    private final String id;

    public IdentifiedObject(String id)
    {
        ParamChecker.assertNotEmpty("id", id);
        this.id = id;
    }

    public String getId()
    {
        return id;
    }
}
