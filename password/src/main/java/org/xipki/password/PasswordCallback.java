// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

/**
 * Callback to get password.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface PasswordCallback {

  /**
   * Initializes me.
   *
   * @param conf
   *          Configuration. Could be {@code null}.
   * @throws PasswordResolverException
   *         if error occurs
   */
  void init(String conf) throws PasswordResolverException;

  /**
   * Resolves the password
   * @param prompt
   *          Prompt shown to use while asking password. Could be {@code null}.
   * @param testToken
   *          Token used to test whether the retrieved password is correct. Could be {@code null}.
   * @return the resolved password
   * @throws PasswordResolverException
   *         if error occurs
   */
  char[] getPassword(String prompt, String testToken) throws PasswordResolverException;

}
