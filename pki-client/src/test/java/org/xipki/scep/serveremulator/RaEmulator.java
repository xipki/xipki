// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.xipki.security.X509Cert;
import org.xipki.util.codec.Args;

import java.security.PrivateKey;

/**
 * RA emulator.
 *
 * @author Lijun Liao (xipki)
 */

public class RaEmulator {

  private final PrivateKey raKey;

  private final X509Cert raCert;

  public RaEmulator(PrivateKey raKey, X509Cert raCert) {
    this.raKey = Args.notNull(raKey, "raKey");
    this.raCert = Args.notNull(raCert, "raCert");
  }

  public PrivateKey raKey() {
    return raKey;
  }

  public X509Cert raCert() {
    return raCert;
  }

}
