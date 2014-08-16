/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

/**
 * @author Lijun Liao
 */

public enum DuplicationMode
{
    FORBIDDEN (1, "forbidden"),
    FORBIDDEN_WITHIN_PROFILE (2, "forbiddenWithinProfile"),
    PERMITTED (3, "permitted");

    private final int mode;
    private final String description;

    private DuplicationMode(int mode, String description)
    {
        this.mode = mode;
        this.description = description;
    }

    public int getMode()
    {
        return mode;
    }

    public String getDescription()
    {
        return description;
    }

    public static DuplicationMode getInstance(String text)
    {
        for(DuplicationMode value : values())
        {
            if(value.description.equalsIgnoreCase(text) ||
                    value.name().equalsIgnoreCase(text) ||
                    Integer.toString(value.mode).equalsIgnoreCase(text))
            {
                return value;
            }
        }

        return null;
    }

    public static DuplicationMode getInstance(int mode)
    {
        for(DuplicationMode value : values())
        {
            if(mode == value.mode)
            {
                return value;
            }
        }

        return null;
    }
}
