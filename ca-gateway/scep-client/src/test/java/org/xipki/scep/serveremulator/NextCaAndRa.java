// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.xipki.security.X509Cert;
import org.xipki.util.Args;

/**
 * Contains the next CA certificate and next RA certificate.
 *
 * @author Lijun Liao
 */

public class NextCaAndRa {

  private final X509Cert caCert;

  private final X509Cert raCert;

  public NextCaAndRa(X509Cert caCert, X509Cert raCert) {
    this.caCert = Args.notNull(caCert, "caCert");
    this.raCert = raCert;
  }

  public X509Cert getCaCert() {
    return caCert;
  }

  public X509Cert getRaCert() {
    return raCert;
  }

}
