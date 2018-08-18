/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import org.xipki.password.callback.FilePasswordCallback;
import org.xipki.password.callback.GuiPasswordCallback;
import org.xipki.password.callback.OBFPasswordCallback;
import org.xipki.password.callback.PBEConsumerPasswordCallback;
import org.xipki.password.callback.PBEGuiPasswordCallback;
import org.xipki.password.callback.PasswordCallback;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class PBESinglePasswordResolver implements SinglePasswordResolver {

  private char[] masterPassword;

  private final Object masterPasswordLock = new Object();

  private String masterPasswordCallback = "PBE-GUI";

  private PasswordCallback masterPwdCallback;

  public PBESinglePasswordResolver() {
  }

  protected char[] getMasterPassword(String encryptedPassword) throws PasswordResolverException {
    synchronized (masterPasswordLock) {
      init();
      if (masterPassword == null) {
        if (masterPwdCallback == null) {
          throw new PasswordResolverException("masterPasswordCallback is not initialized");
        }
        this.masterPassword = masterPwdCallback.getPassword("Please enter the master password",
            encryptedPassword);
      }
      return masterPassword;
    }
  }

  private void init() {
    if (masterPwdCallback != null) {
      return;
    }

    if (StringUtil.isBlank(masterPasswordCallback)) {
      return;
    }

    String type;
    String conf = null;

    int delimIndex = masterPasswordCallback.indexOf(' ');
    if (delimIndex == -1) {
      type = masterPasswordCallback;
    } else {
      type = masterPasswordCallback.substring(0, delimIndex);
      conf = masterPasswordCallback.substring(delimIndex + 1);
    }

    PasswordCallback pwdCallback;
    if ("FILE".equalsIgnoreCase(type)) {
      pwdCallback = new FilePasswordCallback();
    } else if ("GUI".equalsIgnoreCase(type)) {
      pwdCallback = new GuiPasswordCallback();
    } else if ("PBE-GUI".equalsIgnoreCase(type)) {
      pwdCallback = new PBEGuiPasswordCallback();
    } else if ("PBE-Consumer".equalsIgnoreCase(type)) {
      pwdCallback = new PBEConsumerPasswordCallback();
    } else if ("OBF".equalsIgnoreCase(type)) {
      pwdCallback = new OBFPasswordCallback();
      if (conf != null && !StringUtil.startsWithIgnoreCase(conf, "OBF:")) {
        conf = "OBF:" + conf;
      }
    } else {
      throw new RuntimeException("unknown PasswordCallback type '" + type + "'");
    }

    try {
      pwdCallback.init(conf);
    } catch (PasswordResolverException ex) {
      throw new IllegalArgumentException("invalid masterPasswordCallback configuration "
          + masterPasswordCallback + ", " + ex.getClass().getName() + ": " + ex.getMessage());
    }
    this.masterPwdCallback = pwdCallback;
  }

  public void clearMasterPassword() {
    masterPassword = null;
  }

  @Override
  public boolean canResolveProtocol(String protocol) {
    return "PBE".equalsIgnoreCase(protocol);
  }

  @Override
  public char[] resolvePassword(String passwordHint) throws PasswordResolverException {
    return PBEPasswordService.decryptPassword(getMasterPassword(passwordHint), passwordHint);
  }

  @Override
  public String protectPassword(char[] password) throws PasswordResolverException {
    final int iterationCount = 2000;
    return PBEPasswordService.encryptPassword(PBEAlgo.PBEWithHmacSHA256AndAES_256, iterationCount,
        getMasterPassword(null), password);
  }

  public void setMasterPasswordCallback(String masterPasswordCallback) {
    ParamUtil.requireNonBlank("masterPasswordCallback", masterPasswordCallback);
    this.masterPasswordCallback = masterPasswordCallback.trim();
  }

}
