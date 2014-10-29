/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common.cmp;

import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class ProtectionVerificationResult
{
    private final Object requestor;
    private final ProtectionResult protectionResult;

    public ProtectionVerificationResult(Object requestor, ProtectionResult protectionResult)
    {
        ParamChecker.assertNotNull("protectionResult", protectionResult);

        this.requestor = requestor;
        this.protectionResult = protectionResult;
    }

    public Object getRequestor()
    {
        return requestor;
    }

    public ProtectionResult getProtectionResult()
    {
        return protectionResult;
    }

}
