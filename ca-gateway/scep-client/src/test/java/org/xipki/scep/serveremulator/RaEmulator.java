// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.xipki.security.X509Cert;
import org.xipki.util.Args;

import java.security.PrivateKey;

/**
 * RA emulator.
 *
 * @author Lijun Liao
 */

public class RaEmulator {

  private final PrivateKey raKey;

  private final X509Cert raCert;

  public RaEmulator(PrivateKey raKey, X509Cert raCert) {
    this.raKey = Args.notNull(raKey, "raKey");
    this.raCert = Args.notNull(raCert, "raCert");
  }

  public PrivateKey getRaKey() {
    return raKey;
  }

  public X509Cert getRaCert() {
    return raCert;
  }

}
