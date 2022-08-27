/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

import org.xipki.util.exception.ObjectCreationException;

import java.util.Set;

/**
 * Factory to create {@link KeypairGenerator}.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public interface KeypairGeneratorFactory {

  /**
   * Retrieves the types of supported signers.
   * @return lower-case types of supported signers, never {@code null}.
   */
  Set<String> getSupportedKeypairTypes();

  /**
   * Indicates whether a signer of the given {@code type} can be created or not.
   *
   * @param type
   *          Type of the signer. Must not be {@code null}.
   * @return true if signer of the given type can be created, false otherwise.
   */
  boolean canCreateKeypairGenerator(String type);

  /**
   * Creates a new keypair generator.
   * @param type
   *          Type of the keypair generator. Must not be {@code null}.
   * @param conf
   *          Configuration of the keypair generator. May be {@code null}.
   * @param  securityFactory
   *          SecurityFactory.
   *
   * @return new keypair generator.
   * @throws ObjectCreationException
   *         if signer could not be created.
   */
  KeypairGenerator newKeypairGenerator(String type, String conf, SecurityFactory securityFactory)
      throws ObjectCreationException;

}
