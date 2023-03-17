// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.exception.ObjectCreationException;

import java.util.Set;

/**
 * Interface to register {@link KeypairGeneratorFactory} and to create new
 * {@link KeypairGenerator}.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public interface KeypairGeneratorFactoryRegister {

  /**
   * Retrieves the types of supported keypair generators.
   * @return lower-case types of supported generators, never {@code null}.
   */
  Set<String> getSupportedGeneratorTypes();

  /**
   * Creates a new {@link KeypairGenerator}.
   *
   * @param securityFactory
   *          Security factory. Must not be {@code null}.
   * @param type
   *          Type of the keypair generator. Must not be {@code null}.
   * @param conf
   *          Configuration. Must not be {@code null}.
   * @return new keypair generator.
   * @throws ObjectCreationException
   *           If generator could not be created.
   */
  KeypairGenerator newKeypairGenerator(SecurityFactory securityFactory, String type, String conf)
      throws ObjectCreationException;

}
