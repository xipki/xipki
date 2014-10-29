/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.xipki.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public class PKIStatusInfo
{
    private final int status;
    private final int pkiFailureInfo;
    private final String statusMessage;

    public PKIStatusInfo(int status, int pkiFailureInfo, String statusMessage)
    {
        this.status = status;
        this.pkiFailureInfo = pkiFailureInfo;
        this.statusMessage = statusMessage;
    }

    public PKIStatusInfo(int status)
    {
        this.status = status;
        this.pkiFailureInfo = 0;
        this.statusMessage = null;
    }

    public PKIStatusInfo(org.bouncycastle.asn1.cmp.PKIStatusInfo bcPKIStatusInfo)
    {
        this.status = bcPKIStatusInfo.getStatus().intValue();
        if(bcPKIStatusInfo.getFailInfo() != null)
        {
            this.pkiFailureInfo = bcPKIStatusInfo.getFailInfo().intValue();
        }
        else
        {
            this.pkiFailureInfo = 0;
        }
        PKIFreeText text = bcPKIStatusInfo.getStatusString();
        this.statusMessage = text == null ? null : text.getStringAt(0).getString();
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

    @Override
    public String toString()
    {
        return IoCertUtil.formatPKIStatusInfo(status, pkiFailureInfo, statusMessage);
    }

}
