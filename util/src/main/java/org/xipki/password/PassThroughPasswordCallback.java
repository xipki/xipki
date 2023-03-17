// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordCallback;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.Args;

/**
 * A demo PasswordCallback which just pass-through the password.
 *
 * @author Lijun Liao
 * @since 6.2.0
 */
public class PassThroughPasswordCallback implements PasswordCallback {

  private static Logger LOG = LoggerFactory.getLogger(PassThroughPasswordCallback.class);

  private char[] password;

  public PassThroughPasswordCallback() {
    String sepLine =         "===========================================================";
    String msg = sepLine + "\n|| PassThroughPasswordCallback IS ONLY FOR DEMO PURPOSE, ||" +
                           "\n|| DO NOT USE IT IN THE PRODUCTION ENVIRONMENT.          ||\n" + sepLine;
    System.out.println(msg);
    LOG.warn(msg);
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
