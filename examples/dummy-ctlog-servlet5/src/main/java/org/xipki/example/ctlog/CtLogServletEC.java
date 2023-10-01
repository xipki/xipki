// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.example.ctlog;

import org.xipki.util.Base64;

/**
 * The CT Log servlet EC.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogServletEC extends CtLogServlet {

  private static final String privateKey =
        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCA5yyZCYzCoBiIEspXdhwWyhQOmfB6O"
      + "nhFO/g2UCMxkew==";

  private static final String publicKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt13k6XhtxLVQlTmmP9NVgsLF2EA2U0Blp2ug1cm7"
      + "H0ltv7NnrCRq+K87YyiggdGdrKwvDN5/DE1muN/jUditww==";

  public CtLogServletEC() {
    super(Base64.decode(privateKey), Base64.decode(publicKey));
  }

}
