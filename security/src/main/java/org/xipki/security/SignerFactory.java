// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.exception.ObjectCreationException;

import java.util.Set;

/**
 * Factory to create {@link ConcurrentContentSigner}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface SignerFactory {

  /**
   * Retrieves the types of supported signers.
   * @return lower-case types of supported signers, never {@code null}.
   */
  Set<String> getSupportedSignerTypes();

  /**
   * Indicates whether a signer of the given {@code type} can be created or not.
   *
   * @param type
   *          Type of the signer. Must not be {@code null}.
   * @return true if signer of the given type can be created, false otherwise.
   */
  boolean canCreateSigner(String type);

  /**
   * Creates a new signer.
   * @param type
   *          Type of the signer. Must not be {@code null}.
   * @param conf
   *          Configuration of the signer. Must not be {@code null}.
   * @param certificateChain
   *          Certificate chain of the signer. Could be {@code null}.
   *
   * @return new signer.
   * @throws ObjectCreationException
   *         if signer could not be created.
   */
  ConcurrentContentSigner newSigner(String type, SignerConf conf, X509Cert[] certificateChain)
      throws ObjectCreationException;

}
