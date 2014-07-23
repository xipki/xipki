/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public class PKIErrorException extends Exception
{
    private static final long serialVersionUID = 1L;

    private final int status;
    private final int pkiFailureInfo;
    private final String statusMessage;

    public PKIErrorException(int status, int pkiFailureInfo, String statusMessage)
    {
        super(IoCertUtil.formatPKIStatusInfo(status, pkiFailureInfo, statusMessage));
        this.status = status;
        this.pkiFailureInfo = pkiFailureInfo;
        this.statusMessage = statusMessage;
    }

    public PKIErrorException(int status)
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
