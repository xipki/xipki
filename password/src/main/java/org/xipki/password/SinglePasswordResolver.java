// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

/**
 * Single password resolver.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface SinglePasswordResolver {

  boolean canResolveProtocol(String protocol);

  char[] resolvePassword(String passwordHint) throws PasswordResolverException;

  String protectPassword(char[] password) throws PasswordResolverException;

  class OBF implements SinglePasswordResolver {

    public OBF() {
    }

    @Override
    public boolean canResolveProtocol(String protocol) {
      return OBFPasswordService.PROTOCOL_OBF.equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(String passwordHint) {
      return OBFPasswordService.deobfuscate(passwordHint).toCharArray();
    }

    @Override
    public String protectPassword(char[] password) {
      return OBFPasswordService.obfuscate(new String(password));
    }

  } // class OBF

  class PBE implements SinglePasswordResolver {

    private char[] masterPassword;

    private final Object masterPasswordLock = new Object();

    private String masterPasswordCallback = "PBE-GUI";

    private PasswordCallback masterPwdCallback;

    private int iterationCount = 2000;

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

      if (!Args.isBlank(masterPasswordCallback)) {
        this.masterPwdCallback = PasswordCallback.getInstance(masterPasswordCallback);
      }
    } // method init

    public void clearMasterPassword() {
      masterPassword = null;
    }

    @Override
    public boolean canResolveProtocol(String protocol) {
      return PBEPasswordService.PROTOCOL_PBE.equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(String passwordHint) throws PasswordResolverException {
      return PBEPasswordService.decryptPassword(getMasterPassword(passwordHint), passwordHint);
    }

    @Override
    public String protectPassword(char[] password) throws PasswordResolverException {
      return PBEPasswordService.encryptPassword(PBEAlgo.PBEWithHmacSHA256AndAES_256, iterationCount,
          getMasterPassword(null), password);
    }

    public void setMasterPasswordCallback(String masterPasswordCallback) {
      Args.notBlank(masterPasswordCallback, "masterPasswordCallback");
      this.masterPasswordCallback = masterPasswordCallback.trim();
    }

    public void setIterationCount(int iterationCount) {
      this.iterationCount = Args.min(iterationCount, "iterationCount", 1000);
    }

  } // class PBE

}
