/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertificatePolicyQualifier
{
    private final String cpsUri;
    private final String userNotice;

    private CertificatePolicyQualifier(String cpsUri, String userNotice)
    {
        this.cpsUri = cpsUri;
        this.userNotice = userNotice;
    }

    public static CertificatePolicyQualifier getInstanceForUserNotice(String userNotice)
    {
        ParamChecker.assertNotEmpty("userNotice", userNotice);
        return new CertificatePolicyQualifier(null, userNotice);
    }

    public static CertificatePolicyQualifier getInstanceForCpsUri(String cpsUri)
    {
        ParamChecker.assertNotEmpty("cpsUri", cpsUri);
        return new CertificatePolicyQualifier(cpsUri, null);
    }

    public String getCpsUri()
    {
        return cpsUri;
    }

    public String getUserNotice()
    {
        return userNotice;
    }

}
