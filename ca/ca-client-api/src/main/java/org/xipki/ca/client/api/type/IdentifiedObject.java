/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api.type;

import org.xipki.common.ParamChecker;

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
