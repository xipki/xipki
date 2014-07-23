/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

/**
 * @author Lijun Liao
 */

public interface ConcurrentContentSigner
{

    AlgorithmIdentifier getAlgorithmIdentifier();

    /**
     *
     * @return the private key if possible. {@code null} may be returned.
     */
    PrivateKey getPrivateKey();

    X509Certificate getCertificate();

    X509CertificateHolder getCertificateAsBCObject();

    void setCertificateChain(X509Certificate[] certchain);

    X509Certificate[] getCertificateChain();

    X509CertificateHolder[] getCertificateChainAsBCObjects();

    void initialize(String conf, PasswordResolver passwordResolver)
    throws SignerException;

    public ContentSigner borrowContentSigner()
    throws NoIdleSignerException;

    /**
     *
     * @param timeout timeout in milliseconds, 0 for infinitely
     * @return
     * @throws InterruptedException
     */
    public ContentSigner borrowContentSigner(int timeout)
    throws NoIdleSignerException;

    public void returnContentSigner(ContentSigner signer);

    public boolean isHealthy();
}
