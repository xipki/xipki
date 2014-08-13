/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

/**
 * @author Lijun Liao
 */

public enum ValidityMode
{
    STRICT,
    LAX,
    CUTOFF;

    public static ValidityMode getInstance(String text)
    {
        for(ValidityMode value : values())
        {
            if(value.name().equalsIgnoreCase(text))
            {
                return value;
            }
        }

        return null;
    }

}
