// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.xipki.codec.util.Args;
import org.xipki.pkix.cert.X509Cert;

import java.security.PrivateKey;

/**
 * RA emulator.
 *
 * @author Lijun Liao (xipki)
 */

public class RaEmulator {

  private final PrivateKey raKey;

  private final X509Cert raCert;

  private final PrivateKey raEncKey;

  private final X509Cert raEncCert;

  public RaEmulator(PrivateKey raKey, X509Cert raCert) {
    this(raKey, raCert, raKey, raCert);
  }

  public RaEmulator(PrivateKey raKey, X509Cert raCert, PrivateKey raEncKey, X509Cert raEncCert) {
    this.raKey = Args.notNull(raKey, "raKey");
    this.raCert = Args.notNull(raCert, "raCert");
    this.raEncKey = Args.notNull(raEncKey, "raEncKey");
    this.raEncCert = Args.notNull(raEncCert, "raEncCert");
  }

  public PrivateKey raKey() {
    return raKey;
  }

  public X509Cert raCert() {
    return raCert;
  }

  public PrivateKey raEncKey() {
    return raEncKey;
  }

  public X509Cert raEncCert() {
    return raEncCert;
  }

}
