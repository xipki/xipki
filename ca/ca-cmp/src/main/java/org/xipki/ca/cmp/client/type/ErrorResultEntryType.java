/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import org.xipki.ca.common.PKIStatusInfo;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class ErrorResultEntryType extends ResultEntryType
{
    private final PKIStatusInfo statusInfo;

    public ErrorResultEntryType(String id, PKIStatusInfo statusInfo)
    {
        super(id);
        ParamChecker.assertNotNull("statusInfo", statusInfo);
        this.statusInfo = statusInfo;
    }

    public ErrorResultEntryType(String id, int status, int pkiFailureInfo, String statusMessage)
    {
        super(id);
        this.statusInfo = new PKIStatusInfo(status, pkiFailureInfo, statusMessage);
    }

    public ErrorResultEntryType(String id, int status)
    {
        super(id);
        this.statusInfo = new PKIStatusInfo(status);
    }

    public PKIStatusInfo getStatusInfo()
    {
        return statusInfo;
    }
}
