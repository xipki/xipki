// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

/**
 * Password resolver interface.
 *
 * @author Lijun Liao (xipki)
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
  char[] resolvePassword(String passwordHint) throws PasswordResolverException;

  String protectPassword(String protocol, char[] password) throws PasswordResolverException;

}
