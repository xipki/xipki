/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp;

/**
 * @author Lijun Liao
 */

public enum OcspResponseStatus
{
    successfull(0),
    malformedRequest(1),
    internalError(2),
    tryLater(3),
    sigRequired(5),
    unauthorized(6);

    private final int status;
    private OcspResponseStatus(int status)
    {
        this.status = status;
    }

    public static OcspResponseStatus getOCSPResponseStatus(int status)
    {
        for(OcspResponseStatus entry : values())
        {
            if(entry.status == status)
            {
                return entry;
            }
        }

        return null;
    }

    public int getStatus()
    {
        return status;
    }
}
