/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import java.util.Collections;
import java.util.List;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertificatePolicyInformation
{
    private final String certPolicyId;
    private final List<CertificatePolicyQualifier> qualifiers;

    public CertificatePolicyInformation(String certPolicyId, List<CertificatePolicyQualifier> qualifiers)
    {
        ParamChecker.assertNotEmpty("certPolicyId", certPolicyId);
        this.certPolicyId = certPolicyId;
        this.qualifiers = qualifiers == null ? null : Collections.unmodifiableList(qualifiers);
    }

    public String getCertPolicyId()
    {
        return certPolicyId;
    }

    public List<CertificatePolicyQualifier> getQualifiers()
    {
        return qualifiers;
    }

}
