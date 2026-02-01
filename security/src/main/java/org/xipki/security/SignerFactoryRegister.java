// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.extra.exception.ObjectCreationException;

import java.util.Set;

/**
 * Interface to register {@link SignerFactory} and to create new
 * {@link ConcurrentSigner}.
 *
 * @author Lijun Liao (xipki)
 */
public interface SignerFactoryRegister {

  /**
   * Retrieves the types of supported signers.
   * @return lower-case types of supported signers, never {@code null}.
   */
  Set<String> supportedSignerTypes();

  /**
   * Creates a new {@link ConcurrentSigner}.
   *
   * @param securityFactory
   *          Security factory. Must not be {@code null}.
   * @param type
   *          Type of the signer. Must not be {@code null}.
   * @param conf
   *          Configuration. Must not be {@code null}.
   * @param certificateChain
   *          Certificate chain. Could be {@code null}-
   * @return new signer.
   * @throws ObjectCreationException
   *           If signer could not be created.
   */
  ConcurrentSigner newSigner(
      SecurityFactory securityFactory, String type, SignerConf conf,
      X509Cert[] certificateChain) throws ObjectCreationException;

}
