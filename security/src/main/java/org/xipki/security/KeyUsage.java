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

package org.xipki.security;

import static org.xipki.util.Args.notNull;

/**
 * Certificate key usage enum.
 *
 * @author Lijun Liao
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
    notNull(usage, "usage");
    String u = usage.trim();

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
