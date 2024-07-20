// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

/**
 * Password resolver interface.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface PasswordResolver {

  void init(String conf) throws PasswordResolverException;

  boolean canResolveProtocol(String protocol);

  char[] resolvePassword(String passwordHint) throws PasswordResolverException;

  String protectPassword(char[] password) throws PasswordResolverException;

}
