// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.xipki.util.codec.Args;

import java.security.SecureRandom;

/**
 * Parameters for the keystore generation.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class KeystoreGenerationParameters {

  private final char[] password;

  private SecureRandom random;

  private Boolean unsigned;

  public KeystoreGenerationParameters(char[] password) {
    this.password = Args.notNull(password, "password");
  }

  public SecureRandom getRandom() {
    return random;
  }

  public void setRandom(SecureRandom random) {
    this.random = random;
  }

  public char[] getPassword() {
    return password;
  }

  public Boolean getUnsigned() {
    return unsigned;
  }

  public void setUnsigned(Boolean unsigned) {
    this.unsigned = unsigned;
  }

}
