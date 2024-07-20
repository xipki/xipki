// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password.demo;

import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;

/**
 * A demo SinglePasswordResolver which just pass-through the password.
 *
 * @author Lijun Liao (xipki)
 */
public class PassThroughSinglePasswordResolver implements PasswordResolver {

  private static final String protocol = "THRU";

  public PassThroughSinglePasswordResolver() {
    String sepLine =         "===========================================================";
    String msg = sepLine + "\n|| PassThroughSinglePasswordResolver IS ONLY FOR DEMO PURPOSE, ||" +
                           "\n|| DO NOT USE IT IN THE PRODUCTION ENVIRONMENT.          ||\n" + sepLine;
    System.out.println(msg);
  }

  @Override
  public void init(String conf) {
  }

  @Override
  public boolean canResolveProtocol(String protocol) {
    return this.protocol.equalsIgnoreCase(protocol);
  }

  @Override
  public char[] resolvePassword(String passwordHint) throws PasswordResolverException {
    if (!passwordHint.startsWith(protocol + ":")) {
      throw new PasswordResolverException("encrypted password does not start with '" + protocol + ":'");
    }
    return passwordHint.substring(protocol.length() + 1).toCharArray();
  }

  @Override
  public String protectPassword(char[] password) throws PasswordResolverException {
    return protocol + ":" + new String(password);
  }
}
