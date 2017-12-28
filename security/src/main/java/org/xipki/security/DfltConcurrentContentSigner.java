/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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
import java.io.OutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.concurrent.ConcurrentBag;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.password.PasswordResolver;
import org.xipki.security.bc.XiContentSigner;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DfltConcurrentContentSigner implements ConcurrentContentSigner {

    private static final Logger LOG = LoggerFactory.getLogger(DfltConcurrentContentSigner.class);

    private static final AtomicInteger NAME_INDEX = new AtomicInteger(1);

    private static int defaultSignServiceTimeout = 10000; // 10 seconds

    private final String name;

    private final String algorithmName;

    private final ConcurrentBag<ConcurrentBagEntrySigner> signers = new ConcurrentBag<>();

    private final boolean mac;

    private byte[] sha1DigestOfMacKey;

    private final Key signingKey;

    private final AlgorithmCode algorithmCode;

    private PublicKey publicKey;

    private X509Certificate[] certificateChain;

    private X509CertificateHolder[] certificateChainAsBcObjects;

    static {
        final String propKey = "org.xipki.security.signservice.timeout";
        String str = System.getProperty(propKey);
        if (str != null) {
            int vi = Integer.parseInt(str);
            // valid value is between 0 and 60 seconds
            if (vi < 0 || vi > 60 * 1000) {
                LOG.error("invalid {}: {}", propKey, vi);
            } else {
                LOG.info("use {}: {}", propKey, vi);
                defaultSignServiceTimeout = vi;
            }
        }
    }

    public DfltConcurrentContentSigner(final boolean mac, final List<XiContentSigner> signers)
            throws NoSuchAlgorithmException {
        this(mac, signers, null);
    }

    public DfltConcurrentContentSigner(final boolean mac,
            final List<XiContentSigner> signers, final Key signingKey)
            throws NoSuchAlgorithmException {
        ParamUtil.requireNonEmpty("signers", signers);

        this.mac = mac;
        AlgorithmIdentifier algorithmIdentifier = signers.get(0).getAlgorithmIdentifier();
        this.algorithmName = AlgorithmUtil.getSigOrMacAlgoName(algorithmIdentifier);
        this.algorithmCode = AlgorithmUtil.getSigOrMacAlgoCode(algorithmIdentifier);

        for (XiContentSigner signer : signers) {
            this.signers.add(new ConcurrentBagEntrySigner(signer));
        }

        this.signingKey = signingKey;
        this.name = "defaultSigner-" + NAME_INDEX.getAndIncrement();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isMac() {
        return mac;
    }

    public void setSha1DigestOfMacKey(byte[] sha1Digest) {
        if (sha1Digest == null) {
            this.sha1DigestOfMacKey = null;
        } else if (sha1Digest.length == 20) {
            this.sha1DigestOfMacKey = Arrays.copyOf(sha1Digest, 20);
        } else {
            throw new IllegalArgumentException("invalid sha1Digest.length ("
                    + sha1Digest.length + " != 20)");
        }
    }

    @Override
    public byte[] getSha1DigestOfMacKey() {
        return (sha1DigestOfMacKey == null) ? null : Arrays.copyOf(sha1DigestOfMacKey, 20);
    }

    @Override
    public AlgorithmCode algorithmCode() {
        return algorithmCode;
    }

    @Override
    public ConcurrentBagEntrySigner borrowContentSigner()
            throws NoIdleSignerException {
        return borrowContentSigner(defaultSignServiceTimeout);
    }

    /**
     * @param soTimeout timeout in milliseconds, 0 for infinitely.
     */
    @Override
    public ConcurrentBagEntrySigner borrowContentSigner(final int soTimeout)
            throws NoIdleSignerException {
        ConcurrentBagEntrySigner signer = null;
        try {
            signer = signers.borrow(soTimeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
        }

        if (signer == null) {
            throw new NoIdleSignerException("no idle signer available");
        }

        return signer;
    }

    @Override
    public void requiteContentSigner(final ConcurrentBagEntrySigner signer) {
        signers.requite(signer);
    }

    @Override
    public void initialize(final String conf, final PasswordResolver passwordResolver)
            throws XiSecurityException {
    }

    @Override
    public Key getSigningKey() {
        return signingKey;
    }

    @Override
    public void setCertificateChain(final X509Certificate[] certificateChain) {
        if (certificateChain == null || certificateChain.length == 0) {
            this.certificateChain = null;
            this.certificateChainAsBcObjects = null;
            return;
        }

        this.certificateChain = certificateChain;
        setPublicKey(certificateChain[0].getPublicKey());
        final int n = certificateChain.length;

        this.certificateChainAsBcObjects = new X509CertificateHolder[n];
        for (int i = 0; i < n; i++) {
            X509Certificate cert = this.certificateChain[i];
            try {
                this.certificateChainAsBcObjects[i] = new X509CertificateHolder(cert.getEncoded());
            } catch (CertificateEncodingException | IOException ex) {
                throw new IllegalArgumentException(
                        String.format("%s occurred while parsing certificate at index %d: %s",
                                ex.getClass().getName(), i, ex.getMessage()), ex);
            }
        }
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public void setPublicKey(final PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public X509Certificate getCertificate() {
        return (certificateChain != null && certificateChain.length > 0)
                ? certificateChain[0] : null;
    }

    @Override
    public X509CertificateHolder getCertificateAsBcObject() {
        return (certificateChainAsBcObjects != null && certificateChainAsBcObjects.length > 0)
                ? certificateChainAsBcObjects[0] : null;
    }

    @Override
    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    @Override
    public X509CertificateHolder[] getCertificateChainAsBcObjects() {
        return certificateChainAsBcObjects;
    }

    @Override
    public boolean isHealthy() {
        ConcurrentBagEntrySigner signer = null;
        try {
            signer = borrowContentSigner();
            OutputStream stream = signer.value().getOutputStream();
            stream.write(new byte[]{1, 2, 3, 4});
            byte[] signature = signer.value().getSignature();
            return signature != null && signature.length > 0;
        } catch (Exception ex) {
            LogUtil.error(LOG, ex);
            return false;
        } finally {
            if (signer != null) {
                requiteContentSigner(signer);
            }
        }
    }

    @Override
    public String getAlgorithmName() {
        return algorithmName;
    }

    @Override
    public void shutdown() {
    }

    @Override
    public byte[] sign(final byte[] data) throws NoIdleSignerException, SignatureException {
        ConcurrentBagEntrySigner contentSigner = borrowContentSigner();
        try {
            OutputStream signatureStream = contentSigner.value().getOutputStream();
            try {
                signatureStream.write(data);
            } catch (IOException ex) {
                throw new SignatureException(
                        "could not write data to SignatureStream: " + ex.getMessage(), ex);
            }
            return contentSigner.value().getSignature();
        } finally {
            requiteContentSigner(contentSigner);
        }
    }

}
