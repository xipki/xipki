// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.encap;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public class SecretWithEncap {

  private final byte[] secret;

  private final byte[] encap;

  public SecretWithEncap(SecretWithEncapsulation encap) {
    this(Args.notNull(encap, "encap").getSecret(), encap.getEncapsulation());
  }

  public SecretWithEncap(byte[] secret, byte[] encap) {
    this.secret = Args.notEmpty(secret, "secret");
    this.encap  = Args.notEmpty(encap, "encap");
  }

  public byte[] getSecret() {
    return secret;
  }

  public byte[] getEncap() {
    return encap;
  }
}
