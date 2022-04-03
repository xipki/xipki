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

import org.xipki.password.PasswordResolver;

import java.io.Closeable;

/**
 * Concurrent keypair generator.
 *
 * @author Lijun Liao
 * @since 5.4.0
 */

public interface KeypairGenerator extends Closeable {

  String getName();

  void setName(String name);

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

  boolean supports(String keyspec);

  /**
   * Generate keypair for the given keyspec.
   *
   * @param keyspec
   *         Key specification. It has the following format:
   *         <ul>
   *         <li>RSA:   'RSA/'&lt;bit-length&gt; or 'RSA/'&lt;bit-length&gt;'/0x'
   *                    &lt;public exponent in hex&gt;</li>
   *         <li>DSA:   'DSA/'&lt;bit-lenth of P&gt;'/'&lt;bit-lenth of Q&gt;, or
   *                  'DSA/0x'&lt;P in hex&gt;'/0x'&lt;Q in hex&gt;'/0x'&lt;G in hex&gt;</li>
   *         <li>EC:    'EC/'&lt;curve OID&gt;</li>
   *         <li>EdDSA: 'ED25519' or 'ED448'</li>
   *         <li>XDH:   'X25519' or 'X448'</li>
   *         </ul>
   * @return the generated keypair.
   * @throws XiSecurityException
   *         if could not generated keypair.
   */
  KeypairGenResult generateKeypair(String keyspec)
      throws XiSecurityException;

  boolean isHealthy();

}
