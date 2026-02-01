// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;

/**
 * @author Lijun Liao (xipki)
 */
public class SecretKeyWithAlias {

  private final String alias;
  private final SecretKey secretKey;

  public SecretKeyWithAlias(String alias, SecretKey secretKey) {
    this.alias = Args.notNull(alias, "alias");
    this.secretKey = Args.notNull(secretKey, "secretKey");
  }

  public String alias() {
    return alias;
  }

  public SecretKey secretKey() {
    return secretKey;
  }
}
