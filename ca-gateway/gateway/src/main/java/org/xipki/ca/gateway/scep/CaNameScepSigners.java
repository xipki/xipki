// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.util.Args;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class CaNameScepSigners {

  private final ScepSigner defaultSigner;

  private final Map<String, ScepSigner> signers;

  public CaNameScepSigners(CaNameSigners signers) {
    ConcurrentContentSigner signer = signers.getDefaultSigner();
    this.defaultSigner = signer == null ? null : new ScepSigner(signer);

    this.signers = new HashMap<>();
    for (String name : signers.signerNames()) {
      this.signers.put(name, new ScepSigner(signers.getSigner(name)));
    }
  }

  public ScepSigner getSigner(String caName) {
    ScepSigner signer = signers.get(Args.toNonBlankLower(caName, "caName"));
    return signer != null ? signer : defaultSigner;
  }

}
