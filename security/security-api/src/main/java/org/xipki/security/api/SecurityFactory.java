/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.xipki.security.api.p11.P11CryptService;

/**
 * @author Lijun Liao
 */

public interface SecurityFactory
{
    static final String DEFAULT_P11MODULE_NAME = "default";

    Set<String> getPkcs11ModuleNames();

    String getDefaultPkcs11ModuleName();

    PasswordResolver getPasswordResolver();

    ConcurrentContentSigner createSigner(String type, String conf, X509Certificate cert)
    throws SignerException;

    ConcurrentContentSigner createSigner(String type, String conf, X509Certificate[] certs)
    throws SignerException;

    ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
    throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(X509Certificate cert)
    throws InvalidKeyException;

    ContentVerifierProvider getContentVerifierProvider(X509CertificateHolder cert)
    throws InvalidKeyException;

    PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
    throws InvalidKeyException;

    boolean verifyPOPO(CertificationRequest p10Req);

    P11CryptService getP11CryptService(String moduleName)
    throws SignerException;
}
