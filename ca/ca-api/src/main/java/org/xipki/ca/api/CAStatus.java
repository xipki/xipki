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
        for(CAStatus value : values())
        {
            if(value.status.equalsIgnoreCase(status))
            {
                return value;
            }
        }

        return null;
    }

}
