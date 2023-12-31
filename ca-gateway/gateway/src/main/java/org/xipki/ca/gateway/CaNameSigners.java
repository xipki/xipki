// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.security.ConcurrentContentSigner;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.exception.InvalidConfException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CaNameSigners {

  private final ConcurrentContentSigner defaultSigner;

  private final Map<String, ConcurrentContentSigner> signers;

  public CaNameSigners(ConcurrentContentSigner defaultSigner, Map<String, ConcurrentContentSigner> signers)
      throws InvalidConfException {
    if (defaultSigner == null && CollectionUtil.isEmpty(signers)) {
      throw new InvalidConfException("At least one of defaultSigner and signers must be set");
    }

    this.defaultSigner = defaultSigner;
    if (signers == null) {
      this.signers = null;
    } else {
      this.signers = new HashMap<>(signers.size() * 3 / 2);
      for (Map.Entry<String, ConcurrentContentSigner> m : signers.entrySet()) {
        String name = m.getKey().toLowerCase(Locale.ROOT);
        if (this.signers.containsKey(name)) {
          throw new InvalidConfException("at least two signers for the CA " + name + " are set");
        }
        this.signers.put(m.getKey().toLowerCase(Locale.ROOT), m.getValue());
      }
    }
  }

  public ConcurrentContentSigner getSigner(String caName) {
    String loName = Args.toNonBlankLower(caName, "caName");
    if (signers != null) {
      ConcurrentContentSigner signer = signers.get(loName);
      if (signer != null) {
        return signer;
      }
    }

    return defaultSigner;
  }

  public ConcurrentContentSigner getDefaultSigner() {
    return defaultSigner;
  }

  public Set<String> signerNames() {
    return signers == null ? Collections.emptySet() : signers.keySet();
  }

}
