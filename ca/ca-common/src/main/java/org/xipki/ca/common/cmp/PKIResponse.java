/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.common.cmp;

import org.bouncycastle.cert.cmp.GeneralPKIMessage;

/**
 * @author Lijun Liao
 */

public class PKIResponse
{
    private final GeneralPKIMessage pkiMessage;
    private ProtectionVerificationResult protectionVerificationResult;

    public PKIResponse(GeneralPKIMessage pkiMessage)
    {
        this.pkiMessage = pkiMessage;
    }

    public boolean hasProtection()
    {
        return pkiMessage.hasProtection();
    }

    public GeneralPKIMessage getPkiMessage()
    {
        return pkiMessage;
    }

    public ProtectionVerificationResult getProtectionVerificationResult()
    {
        return protectionVerificationResult;
    }

    public void setProtectionVerificationResult(ProtectionVerificationResult protectionVerificationResult)
    {
        this.protectionVerificationResult = protectionVerificationResult;
    }

}
