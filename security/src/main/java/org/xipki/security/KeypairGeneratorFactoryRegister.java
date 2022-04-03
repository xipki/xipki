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

import org.xipki.util.ObjectCreationException;

import java.util.Set;

/**
 * Interface to register {@link KeypairGeneratorFactory} and to create new
 * {@link KeypairGenerator}.
 *
 * @author Lijun Liao
 * @since 5.4.0
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
