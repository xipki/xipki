/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api.type;

/**
 * @author Lijun Liao
 */

public class ErrorResultType implements CmpResultType
{
    private final int status;
    private final int pkiFailureInfo;
    private final String statusMessage;

    public ErrorResultType(int status, int pkiFailureInfo, String statusMessage)
    {
        this.status = status;
        this.pkiFailureInfo = pkiFailureInfo;
        this.statusMessage = statusMessage;
    }

    public ErrorResultType(int status)
    {
        this.status = status;
        this.pkiFailureInfo = 0;
        this.statusMessage = null;
    }

    public int getStatus()
    {
        return status;
    }

    public int getPkiFailureInfo()
    {
        return pkiFailureInfo;
    }

    public String getStatusMessage()
    {
        return statusMessage;
    }

}
