/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class SubjectInfo
{
    private final X500Name grantedSubject;
    private final String warning;

    public SubjectInfo(X500Name grantedSubject, String warning)
    {
        ParamChecker.assertNotNull("grantedSubject", grantedSubject);

        this.grantedSubject = grantedSubject;
        this.warning = warning;
    }

    public X500Name getGrantedSubject()
    {
        return grantedSubject;
    }

    public String getWarning()
    {
        return warning;
    }

}
