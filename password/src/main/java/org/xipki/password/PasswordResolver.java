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

package org.xipki.password;

/**
 * Password resolver interface.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface PasswordResolver {

  /**
   * Resolve the password.
   * @param passwordHint
   *          Hint of the password. Must not be {@code null}.
   * @return the resolved password
   * @throws PasswordResolverException
   *         if cannot resolve the password
   */
  char[] resolvePassword(String passwordHint)
      throws PasswordResolverException;

  String protectPassword(String protocol, char[] password)
      throws PasswordResolverException;

}
