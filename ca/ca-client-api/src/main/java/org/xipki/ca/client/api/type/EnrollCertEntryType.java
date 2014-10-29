/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api.type;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class EnrollCertEntryType
{
    private final CertificationRequest p10Request;
    private final String profile;

    public EnrollCertEntryType(CertificationRequest p10Request, String profile)
    {
        ParamChecker.assertNotNull("p10Request", p10Request);
        ParamChecker.assertNotEmpty("profile", profile);

        this.p10Request = p10Request;
        this.profile = profile;
    }

    public CertificationRequest getP10Request()
    {
        return p10Request;
    }

    public String getProfile()
    {
        return profile;
    }

}
