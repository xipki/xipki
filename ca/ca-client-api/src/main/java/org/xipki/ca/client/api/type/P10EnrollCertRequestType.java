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

public class P10EnrollCertRequestType extends IdentifiedObject
{
    private final String certProfile;
    private final CertificationRequest p10Req;

    public P10EnrollCertRequestType(String id, String certProfile, CertificationRequest p10Req)
    {
        super(id);
        ParamChecker.assertNotNull("p10Req", p10Req);

        this.certProfile = certProfile;
        this.p10Req = p10Req;
    }

    public CertificationRequest getP10Req()
    {
        return p10Req;
    }

    public String getCertProfile()
    {
        return certProfile;
    }
}
