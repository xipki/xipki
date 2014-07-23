/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common;

import org.bouncycastle.asn1.crmf.CertId;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertIDOrError
{
    private final CertId certId;
    private final PKIStatusInfo error;

    public CertIDOrError(CertId certId)
    {
        ParamChecker.assertNotNull("certId", certId);

        this.certId = certId;
        this.error = null;
    }

    public CertIDOrError(PKIStatusInfo error)
    {
        ParamChecker.assertNotNull("error", error);

        this.certId = null;
        this.error = error;
    }

    public CertId getCertId()
    {
        return certId;
    }

    public PKIStatusInfo getError()
    {
        return error;
    }

}
