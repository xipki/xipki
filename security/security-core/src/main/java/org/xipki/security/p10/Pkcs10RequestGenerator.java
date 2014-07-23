/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p10;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.security.NopPasswordResolver;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class Pkcs10RequestGenerator
{

    public PKCS10CertificationRequest generateRequest(
            SecurityFactory securityFactory,
            String signerType, String signerConf,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            String subject)
    throws PasswordResolverException, SignerException
    {
        X500Name subjectDN = new X500Name(subject);
        return generateRequest(securityFactory, signerType, signerConf, subjectPublicKeyInfo, subjectDN);
    }

    public PKCS10CertificationRequest generateRequest(
            SecurityFactory securityFactory,
            String signerType, String signerConf,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            X500Name subjectDN)
    throws PasswordResolverException, SignerException
    {
        ConcurrentContentSigner signer = securityFactory.createSigner(signerType, signerConf,
                (X509Certificate[]) null, NopPasswordResolver.INSTANCE);
        ContentSigner contentSigner;
        try
        {
            contentSigner = signer.borrowContentSigner();
        } catch (NoIdleSignerException e)
        {
            throw new SignerException(e);
        }
        try
        {
            return generateRequest(contentSigner, subjectPublicKeyInfo, subjectDN);
        }finally
        {
            signer.returnContentSigner(contentSigner);
        }
    }

    public PKCS10CertificationRequest generateRequest(
            ContentSigner contentSigner,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            X500Name subjectDN)
    {
        PKCS10CertificationRequestBuilder p10ReqBuilder =
                new PKCS10CertificationRequestBuilder(subjectDN, subjectPublicKeyInfo);

        return p10ReqBuilder.build(contentSigner);
    }

}
