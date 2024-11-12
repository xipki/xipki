// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.Args;

/**
 * Certificate key usage enum.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum KeyUsage {

  digitalSignature(0,  org.bouncycastle.asn1.x509.KeyUsage.digitalSignature),
  contentCommitment(1, org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation, "nonRepudiation"),
  keyEncipherment(2,   org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment),
  dataEncipherment(3,  org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment),
  keyAgreement(4,      org.bouncycastle.asn1.x509.KeyUsage.keyAgreement),
  keyCertSign(5,       org.bouncycastle.asn1.x509.KeyUsage.keyCertSign),
  cRLSign(6,           org.bouncycastle.asn1.x509.KeyUsage.cRLSign),
  encipherOnly(7,      org.bouncycastle.asn1.x509.KeyUsage.encipherOnly),
  decipherOnly(8,      org.bouncycastle.asn1.x509.KeyUsage.decipherOnly);

  private final int bit;

  private final int bcUsage;

  private final String[] names;

  KeyUsage(int bit, int bcUsage, String... aliases) {
    this.bit = bit;
    this.bcUsage = bcUsage;
    int len = aliases == null ? 1 : 1 + aliases.length;
    this.names = new String[len];
    this.names[0] = name();
    if (len > 1) {
      System.arraycopy(aliases, 0, names, 1, len - 1);
    }
  }

  public int getBit() {
    return bit;
  }

  public int getBcUsage() {
    return bcUsage;
  }

  public String getName() {
    return names[0];
  }

  public static KeyUsage getKeyUsage(String usage) {
    String u = Args.notNull(usage, "usage").trim();

    for (KeyUsage ku : KeyUsage.values()) {
      for (String name : ku.names) {
        if (name.equalsIgnoreCase(u)) {
          return ku;
        }
      }

      if (Integer.toString(ku.bit).equals(u)) {
        return ku;
      }
    }

    throw new IllegalArgumentException("invalid KeyUsage " + usage);
  }

  public static KeyUsage getKeyUsage(int bit) {
    for (KeyUsage ku : KeyUsage.values()) {
      if (ku.bit == bit) {
        return ku;
      }
    }

    throw new IllegalArgumentException("invalid KeyUsage(bit) " + bit);
  }

  public static KeyUsage getKeyUsageFromBcUsage(int bcUsage) {
    for (KeyUsage ku : KeyUsage.values()) {
      if (ku.bcUsage == bcUsage) {
        return ku;
      }
    }

    throw new IllegalArgumentException("invalid KeyUsage(bcUsage) " + bcUsage);
  }

}
