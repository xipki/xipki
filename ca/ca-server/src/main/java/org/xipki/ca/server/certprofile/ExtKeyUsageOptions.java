/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class ExtKeyUsageOptions
{
    private final List<ExtKeyUsageOption> options;

    public ExtKeyUsageOptions(List<ExtKeyUsageOption> options)
    {
        ParamChecker.assertNotEmpty("options", options);
        this.options = options;
    }

    public Set<ASN1ObjectIdentifier> getExtKeyusage(EnvironmentParameterResolver pr)
    {
        for(ExtKeyUsageOption o : options)
        {
            Condition c = o.getCondition();
            if(c == null || c.satisfy(pr))
            {
                return o.getExtKeyusages();
            }
        }

        return null;
    }

}
