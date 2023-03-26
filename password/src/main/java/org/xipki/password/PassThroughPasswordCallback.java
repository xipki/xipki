// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

/**
 * A demo PasswordCallback which just pass-through the password.
 *
 * @author Lijun Liao (xipki)
 * @since 6.2.0
 */
public class PassThroughPasswordCallback implements PasswordCallback {

  private char[] password;

  public PassThroughPasswordCallback() {
    String sepLine =         "===========================================================";
    String msg = sepLine + "\n|| PassThroughPasswordCallback IS ONLY FOR DEMO PURPOSE, ||" +
                           "\n|| DO NOT USE IT IN THE PRODUCTION ENVIRONMENT.          ||\n" + sepLine;
    System.out.println(msg);
  }

  @Override
  public void init(String conf) throws PasswordResolverException {
    this.password = Args.notBlank(conf, "conf").toCharArray();
  }

  @Override
  public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
    return password.clone();
  }

}
