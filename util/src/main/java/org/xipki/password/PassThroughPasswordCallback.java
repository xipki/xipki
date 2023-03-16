/*
 *
 * Copyright (c) 2013 - 2023 Lijun Liao
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
