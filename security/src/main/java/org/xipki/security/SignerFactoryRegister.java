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

import java.security.cert.X509Certificate;
import java.util.Set;

import org.xipki.util.ObjectCreationException;

/**
 * Interface to register {@link SignerFactory} and to create new
 * {@link ConcurrentContentSigner}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface SignerFactoryRegister {

  /**
   * Retrieves the types of supported signers.
   * @return lower-case types of supported signers, never {@code null}.
   */
  Set<String> getSupportedSignerTypes();

  /**
   * Creates a new {@link ConcurrentContentSigner}.
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
  ConcurrentContentSigner newSigner(SecurityFactory securityFactory, String type, SignerConf conf,
      X509Certificate[] certificateChain) throws ObjectCreationException;

  void refreshTokenForSignerType(String signerType) throws XiSecurityException;

}
