// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.sign;

import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.X509Cert;

import java.security.Key;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Concurrent {@link ContentSigner}.
 *
 * @author Lijun Liao (xipki)
 */
public interface ConcurrentSigner {

  String getName();

  /**
   * Returns the algorithm.
   * @return algorithm
   */
  SignAlgo getAlgorithm();

  boolean isMac();

  byte[] getSha1OfMacKey();

  /**
   * Get the signing key.
   * @return the signing key if possible. {@code null} may be returned.
   */
  Key getSigningKey();

  /**
   * Sets the public key.
   * @param publicKey
   *          Public key of this signer. Must not be {@code null}.
   */
  void setPublicKey(PublicKey publicKey);

  PublicKey getPublicKey();

  X509Cert getX509Cert();

  /**
   * Set the CertificateChain.
   *
   * @param certchain
   *          Certificate chain of this signer. Could be {@code null}.
   */
  void setX509CertChain(X509Cert[] certchain);

  X509Cert[] getX509CertChain();

  /**
   * Initializes me.
   * @param conf
   *          Configuration. Could be {@code null}.
   * @throws XiSecurityException
   *         if error during the initialization occurs.
   */
  void initialize(String conf) throws XiSecurityException;

  /**
   * Sign the data.
   * @param data
   *          Data to be signed. Must not be {@code null}.
   * @return the signature
   * @throws NoIdleSignerException
   *         If no idle signer is available
   * @throws SignatureException
   *         If could not sign the data.
   */
  byte[] x509sign(byte[] data)
      throws NoIdleSignerException, SignatureException;

  /**
   * Sign the data.
   * @param data
   *          Data to be signed. Must not be {@code null}.
   * @return the signature
   * @throws NoIdleSignerException
   *         If no idle signer is available
   * @throws SignatureException
   *         If could not sign the data.
   */
  byte[][] x509sign(byte[][] data)
      throws NoIdleSignerException, SignatureException;

  /**
   * Borrows a signer with implementation-dependent default timeout.
   * @return the signer
   * @throws NoIdleSignerException
   *         If no idle signer is available
   */
  Signer borrowSigner() throws NoIdleSignerException;

  /**
   * Borrows a signer with the given {@code soTimeout}.
   * @param soTimeout timeout in milliseconds, 0 for infinitely.
   * @return the signer
   * @throws NoIdleSignerException
   *         If no idle signer is available
   */
  Signer borrowSigner(int soTimeout) throws NoIdleSignerException;

  void requiteSigner(Signer signer);

  boolean isHealthy();

  void close();
}
