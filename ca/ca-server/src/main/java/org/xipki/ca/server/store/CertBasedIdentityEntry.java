/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.store;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author Lijun Liao
 */

class CertBasedIdentityEntry
{
    private final int id;
    private final String subject;
    private final byte[] sha1Fp;
    private final byte[] cert;

    CertBasedIdentityEntry(int id, String subject, String hexSha1Fp, String b64Cert)
    {
        super();
        this.id = id;
        this.subject = subject;
        this.sha1Fp = Hex.decode(hexSha1Fp);
        this.cert = Base64.decode(b64Cert);
    }

    int getId()
    {
        return id;
    }

    String getSubject()
    {
        return subject;
    }

    boolean matchSha1Fp(byte[] sha1Fp)
    {
        return Arrays.equals(this.sha1Fp, sha1Fp);
    }

    boolean matchCert(byte[] encodedCert)
    {
        return Arrays.equals(this.cert, encodedCert);
    }
}
