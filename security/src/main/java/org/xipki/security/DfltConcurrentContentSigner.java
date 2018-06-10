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
import org.xipki.password.PasswordResolver;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.concurrent.ConcurrentBag;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DfltConcurrentContentSigner implements ConcurrentContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(DfltConcurrentContentSigner.class);

  private static final AtomicInteger NAME_INDEX = new AtomicInteger(1);

  private static int defaultSignServiceTimeout = 10000; // 10 seconds

  private final ConcurrentBag<ConcurrentBagEntrySigner> signers = new ConcurrentBag<>();

  private final String name;

  private final String algorithmName;

  private final boolean mac;

  private byte[] sha1OfMacKey;

  private final Key signingKey;

  private final AlgorithmCode algorithmCode;

  private PublicKey publicKey;

  private X509Certificate[] certificateChain;

  private X509CertificateHolder[] bcCertificateChain;

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

  public DfltConcurrentContentSigner(boolean mac, List<XiContentSigner> signers)
      throws NoSuchAlgorithmException {
    this(mac, signers, null);
  }

  public DfltConcurrentContentSigner(boolean mac, List<XiContentSigner> signers, Key signingKey)
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

  public void setSha1DigestOfMacKey(byte[] digest) {
    if (digest == null) {
      this.sha1OfMacKey = null;
    } else if (digest.length == 20) {
      this.sha1OfMacKey = Arrays.copyOf(digest, 20);
    } else {
      throw new IllegalArgumentException("invalid sha1Digest.length (" + digest.length + " != 20)");
    }
  }

  @Override
  public byte[] getSha1OfMacKey() {
    return (sha1OfMacKey == null) ? null : Arrays.copyOf(sha1OfMacKey, 20);
  }

  @Override
  public AlgorithmCode getAlgorithmCode() {
    return algorithmCode;
  }

  @Override
  public ConcurrentBagEntrySigner borrowSigner() throws NoIdleSignerException {
    return borrowSigner(defaultSignServiceTimeout);
  }

  /**
   * TODO.
   * @param soTimeout timeout in milliseconds, 0 for infinitely.
   */
  @Override
  public ConcurrentBagEntrySigner borrowSigner(int soTimeout) throws NoIdleSignerException {
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
  public void requiteSigner(ConcurrentBagEntrySigner signer) {
    signers.requite(signer);
  }

  @Override
  public void initialize(String conf, PasswordResolver passwordResolver)
      throws XiSecurityException {
  }

  @Override
  public Key getSigningKey() {
    return signingKey;
  }

  @Override
  public void setCertificateChain(X509Certificate[] certificateChain) {
    if (CollectionUtil.isEmpty(certificateChain)) {
      this.certificateChain = null;
      this.bcCertificateChain = null;
      return;
    }

    this.certificateChain = certificateChain;
    setPublicKey(certificateChain[0].getPublicKey());
    final int n = certificateChain.length;
    this.bcCertificateChain = new X509CertificateHolder[n];

    for (int i = 0; i < n; i++) {
      X509Certificate cert = this.certificateChain[i];
      try {
        this.bcCertificateChain[i] = new X509CertificateHolder(cert.getEncoded());
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
  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public X509Certificate getCertificate() {
    return CollectionUtil.isEmpty(certificateChain) ? null : certificateChain[0];
  }

  @Override
  public X509CertificateHolder getBcCertificate() {
    return CollectionUtil.isEmpty(bcCertificateChain) ? null : bcCertificateChain[0];
  }

  @Override
  public X509Certificate[] getCertificateChain() {
    return certificateChain;
  }

  @Override
  public X509CertificateHolder[] getBcCertificateChain() {
    return bcCertificateChain;
  }

  @Override
  public boolean isHealthy() {
    ConcurrentBagEntrySigner signer = null;
    try {
      signer = borrowSigner();
      OutputStream stream = signer.value().getOutputStream();
      stream.write(new byte[]{1, 2, 3, 4});
      byte[] signature = signer.value().getSignature();
      return signature != null && signature.length > 0;
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
      return false;
    } finally {
      if (signer != null) {
        requiteSigner(signer);
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
  public byte[] sign(byte[] data) throws NoIdleSignerException, SignatureException {
    ConcurrentBagEntrySigner signer = borrowSigner();
    try {
      OutputStream signatureStream = signer.value().getOutputStream();
      try {
        signatureStream.write(data);
      } catch (IOException ex) {
        throw new SignatureException(
            "could not write data to SignatureStream: " + ex.getMessage(), ex);
      }
      return signer.value().getSignature();
    } finally {
      requiteSigner(signer);
    }
  }

}
