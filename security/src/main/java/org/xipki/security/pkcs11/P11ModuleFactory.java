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

package org.xipki.security.pkcs11;

/**
 * Factory to create {@link P11Module}.
 *
 * @author Lijun Liao
 * @since 3.0.1
 */

public interface P11ModuleFactory {

  /**
   * Indicates whether a PKCS#11 module of the given {@code type} can be created or not.
   *
   * @param type
   *          Type of the signer. Must not be {@code null}.
   * @return true if PKCS#11 module of the given type can be created, false otherwise.
   */
  boolean canCreateModule(String type);

  /**
   * Creates a new signer.
   * @param conf
   *          Configuration of the PKCS#11 module. Must not be {@code null}.
   *
   * @return new PKCS#11 module.
   * @throws P11TokenException
   *         if PKCS#11 module could not be created.
   */
  P11Module newModule(P11ModuleConf conf) throws P11TokenException;

}
