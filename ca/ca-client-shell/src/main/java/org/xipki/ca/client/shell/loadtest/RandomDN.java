/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.loadtest;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public enum RandomDN
{
    O,
    OU,
    CN;

    static RandomDN getInstance(String text)
    {
        ParamChecker.assertNotNull("text", text);
        for(RandomDN value : values())
        {
            if(value.name().equalsIgnoreCase(text))
            {
                return value;
            }
        }
        return null;
    }
}
