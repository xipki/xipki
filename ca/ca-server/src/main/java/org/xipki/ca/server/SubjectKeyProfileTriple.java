/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

/**
 * @author Lijun Liao
 */

public class SubjectKeyProfileTriple
{
    private final int certId;
    private final String subjectFp;
    private final String keyFp;
    private final String profile;
    private final boolean revoked;

    public SubjectKeyProfileTriple(int certId, String subjectFp, String keyFp, String profile, boolean revoked)
    {
        super();
        this.certId = certId;
        this.subjectFp = subjectFp;
        this.keyFp = keyFp;
        this.profile = profile;
        this.revoked = revoked;
    }

    public int getCertId()
    {
        return certId;
    }

    public String getSubjectFp()
    {
        return subjectFp;
    }

    public String getKeyFp()
    {
        return keyFp;
    }

    public String getProfile()
    {
        return profile;
    }

    public boolean isRevoked()
    {
        return revoked;
    }
}
