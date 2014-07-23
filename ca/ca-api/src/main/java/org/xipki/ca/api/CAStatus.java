/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api;

/**
 * @author Lijun Liao
 */

public enum CAStatus
{
    PENDING("pending"),
    ACTIVE ("active"),
    INACTIVE ("inactive");

    private String status;

    private CAStatus(String status)
    {
        this.status = status;
    }

    public String getStatus()
    {
        return status;
    }

    public static CAStatus getCAStatus(String status)
    {
        if(PENDING.status.equalsIgnoreCase(status))
        {
            return PENDING;
        }
        else if(ACTIVE.status.equalsIgnoreCase(status))
        {
            return ACTIVE;
        }
        else if(INACTIVE.status.equalsIgnoreCase(status))
        {
            return INACTIVE;
        }
        else
        {
            return null;
        }
    }

}
