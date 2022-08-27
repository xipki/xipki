/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.bouncycastle.operator.ContentSigner;
import org.xipki.password.PasswordResolver;

import java.io.Closeable;
import java.security.Key;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Concurrent {@link ContentSigner}.
 *
 * @author Lijun Liao
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
   *         if could not sign the data.
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
   *         if could not sign the data.
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
