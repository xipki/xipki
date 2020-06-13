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

import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * Single password resolver.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface SinglePasswordResolver {

  boolean canResolveProtocol(String protocol);

  char[] resolvePassword(String passwordHint) throws PasswordResolverException;

  String protectPassword(char[] password) throws PasswordResolverException;

  // CHECKSTYLE:SKIP
  public static class OBF implements SinglePasswordResolver {

    public OBF() {
    }

    @Override
    public boolean canResolveProtocol(String protocol) {
      return "OBF".equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(String passwordHint) throws PasswordResolverException {
      return OBFPasswordService.deobfuscate(passwordHint).toCharArray();
    }

    @Override
    public String protectPassword(char[] password) throws PasswordResolverException {
      return OBFPasswordService.obfuscate(new String(password));
    }

  } // class OBF

  // CHECKSTYLE:SKIP
  public static class PBE implements SinglePasswordResolver {

    private char[] masterPassword;

    private final Object masterPasswordLock = new Object();

    private String masterPasswordCallback = "PBE-GUI";

    private PasswordCallback masterPwdCallback;

    public PBE() {
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
        type = masterPasswordCallback.toUpperCase();
      } else {
        type = masterPasswordCallback.substring(0, delimIndex).toUpperCase();
        conf = masterPasswordCallback.substring(delimIndex + 1);
      }

      PasswordCallback pwdCallback;
      if ("FILE".equals(type)) {
        pwdCallback = new PasswordCallback.File();
      } else if ("GUI".equals(type)) {
        pwdCallback = new PasswordCallback.Gui();
      } else if ("PBE-GUI".equals(type)) {
        pwdCallback = new PasswordCallback.PBEGui();
      } else if ("OBF".equals(type)) {
        pwdCallback = new PasswordCallback.OBF();
        if (conf != null && !StringUtil.startsWithIgnoreCase(conf, "OBF:")) {
          conf = StringUtil.concat("OBF:", conf);
        }
      } else {
        throw new IllegalStateException("unknown PasswordCallback type '" + type + "'");
      }

      try {
        pwdCallback.init(conf);
      } catch (PasswordResolverException ex) {
        throw new IllegalArgumentException("invalid masterPasswordCallback configuration "
            + masterPasswordCallback + ", " + ex.getClass().getName() + ": " + ex.getMessage());
      }
      this.masterPwdCallback = pwdCallback;
    } // method init

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
      Args.notBlank(masterPasswordCallback, "masterPasswordCallback");
      this.masterPasswordCallback = masterPasswordCallback.trim();
    }

  } // class PBE

}
