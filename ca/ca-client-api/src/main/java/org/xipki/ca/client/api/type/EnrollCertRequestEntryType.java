/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api.type;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class EnrollCertRequestEntryType extends IdentifiedObject
{
    private final String certProfile;

    private final CertRequest certReq;
    private final ProofOfPossession popo;

    public EnrollCertRequestEntryType(String id, String certProfile,
            CertRequest certReq, ProofOfPossession popo)
    {
        super(id);
        ParamChecker.assertNotNull("certReq", certReq);

        this.certProfile = certProfile;
        this.certReq = certReq;
        this.popo = popo;
    }

    public String getCertProfile()
    {
        return certProfile;
    }

    public CertRequest getCertReq()
    {
        return certReq;
    }

    public ProofOfPossession getPopo()
    {
        return popo;
    }

}
