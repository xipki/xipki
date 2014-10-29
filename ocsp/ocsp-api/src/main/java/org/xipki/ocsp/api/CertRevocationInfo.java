/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.api;

import java.util.Date;

/**
 * @author Lijun Liao
 */

public class CertRevocationInfo
{
    private final int reason;
    private final Date revocationTime;
    private final Date invalidityTime;

    public CertRevocationInfo(int reason, Date revocationTime, Date invalidityTime)
    {
        this.reason = reason;
        this.revocationTime = revocationTime;
        this.invalidityTime = invalidityTime;
    }

    public int getReason()
    {
        return reason;
    }

    public Date getRevocationTime()
    {
        return revocationTime;
    }

    public Date getInvalidityTime()
    {
        return invalidityTime;
    }

}
