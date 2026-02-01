// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import java.util.Collections;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public enum AllowKeyMode {
  EC_SECP,
  ED25519,
  ED448,
  X25519,
  X448,
  EC,
  RSA,
  SM2,
  MLDSA,
  MLKEM,
  COMPSIG,
  COMPKEM,
  EDDSA(ED25519, ED448),
  XDH(X25519, X448),
  ALL_SIGN(EC, RSA, SM2, EDDSA, MLDSA, COMPSIG),
  ALL_ENC(EC, RSA, XDH, SM2, MLKEM, COMPKEM),
  ALL_KA(XDH),
  ALL(ALL_SIGN, ALL_ENC);

  private final List<AllowKeyMode> implies;

  AllowKeyMode(AllowKeyMode... implies) {
    if (implies == null) {
      this.implies = Collections.emptyList();
    } else {
      this.implies = List.of(implies);
    }
  }

  public List<AllowKeyMode> implies() {
    return implies;
  }

}
