/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security;

import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.xipki.password.PasswordResolver;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface ConcurrentContentSigner {

    String getName();

    String getAlgorithmName();

    /**
     * Returns the algorithm code in XiPKI context.
     * @return algorithm code
     */
    AlgorithmCode algorithmCode();

    boolean isMac();

    byte[] getSha1DigestOfMacKey();

    /**
     * Get the signing key.
     * @return the signing key if possible. {@code null} may be returned.
     */
    Key getSigningKey();

    /**
     *
     * @param publicKey
     *          Public key of this signer. Must not be {@code null}.
     */
    void setPublicKey(PublicKey publicKey);

    PublicKey getPublicKey();

    X509Certificate getCertificate();

    X509CertificateHolder getCertificateAsBcObject();

    /**
     *
     * @param certchain
     *          Certificate chain of this signer. Could be {@code null}.
     */
    void setCertificateChain(X509Certificate[] certchain);

    X509Certificate[] getCertificateChain();

    X509CertificateHolder[] getCertificateChainAsBcObjects();

    /**
     *
     * @param conf
     *          Configuration. Could be {@code null}.
     * @param passwordResolver
     *          Password resolver. Could be {@code null}.
     */
    void initialize(String conf, PasswordResolver passwordResolver)
            throws XiSecurityException;

    /**
     *
     * @param data
     *          Data to be signed. Must not be {@code null}.
     */
    byte[] sign(byte[] data) throws NoIdleSignerException, IOException;

    /**
     * borrow a ContentSigner with implementation-dependent default timeout.
     */
    ConcurrentBagEntrySigner borrowContentSigner()
            throws NoIdleSignerException;

    /**
     * @param timeout timeout in milliseconds, 0 for infinitely.
     */
    ConcurrentBagEntrySigner borrowContentSigner(final int soTimeout)
            throws NoIdleSignerException;

    void requiteContentSigner(final ConcurrentBagEntrySigner signer);

    boolean isHealthy();

    void shutdown();

}
