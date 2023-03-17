// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.operator.ContentSigner;
import org.xipki.password.PasswordResolver;

import java.io.Closeable;
import java.security.Key;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Concurrent {@link ContentSigner}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface ConcurrentContentSigner extends Closeable {

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

  X509Cert getCertificate();

  /**
   * Set the CertificateChain.
   *
   * @param certchain
   *          Certificate chain of this signer. Could be {@code null}.
   */
  void setCertificateChain(X509Cert[] certchain);

  X509Cert[] getCertificateChain();

  /**
   * Initializes me.
   * @param conf
   *          Configuration. Could be {@code null}.
   * @param passwordResolver
   *          Password resolver. Could be {@code null}.
   * @throws XiSecurityException
   *         if error during the initialization occurs.
   */
  void initialize(String conf, PasswordResolver passwordResolver)
      throws XiSecurityException;

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
  byte[] sign(byte[] data) throws NoIdleSignerException, SignatureException;

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
  byte[][] sign(byte[][] data) throws NoIdleSignerException, SignatureException;

  /**
   * Borrows a signer with implementation-dependent default timeout.
   * @return the signer
   * @throws NoIdleSignerException
   *         If no idle signer is available
   */
  ConcurrentBagEntrySigner borrowSigner() throws NoIdleSignerException;

  /**
   * Borrows a signer with the given {@code soTimeout}.
   * @param soTimeout timeout in milliseconds, 0 for infinitely.
   * @return the signer
   * @throws NoIdleSignerException
   *         If no idle signer is available
   */
  ConcurrentBagEntrySigner borrowSigner(int soTimeout) throws NoIdleSignerException;

  void requiteSigner(ConcurrentBagEntrySigner signer);

  boolean isHealthy();

}
