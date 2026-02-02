// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class CaNameSigners {

  private final ConcurrentSigner defaultSigner;

  private final Map<String, ConcurrentSigner> signers;

  public CaNameSigners(ConcurrentSigner defaultSigner,
                       Map<String, ConcurrentSigner> signers)
      throws InvalidConfException {
    if (defaultSigner == null && CollectionUtil.isEmpty(signers)) {
      throw new InvalidConfException(
          "At least one of defaultSigner and signers must be set");
    }

    this.defaultSigner = defaultSigner;
    if (signers == null) {
      this.signers = null;
    } else {
      this.signers = new HashMap<>(signers.size() * 3 / 2);
      for (Map.Entry<String, ConcurrentSigner> m : signers.entrySet()) {
        String name = m.getKey().toLowerCase(Locale.ROOT);
        if (this.signers.containsKey(name)) {
          throw new InvalidConfException(
              "at least two signers for the CA " + name + " are set");
        }
        this.signers.put(m.getKey().toLowerCase(Locale.ROOT), m.getValue());
      }
    }
  }

  public ConcurrentSigner getSigner(String caName) {
    String loName = Args.toNonBlankLower(caName, "caName");
    if (signers != null) {
      ConcurrentSigner signer = signers.get(loName);
      if (signer != null) {
        return signer;
      }
    }

    return defaultSigner;
  }

  public ConcurrentSigner defaultSigner() {
    return defaultSigner;
  }

  public Set<String> signerNames() {
    return signers == null ? Collections.emptySet() : signers.keySet();
  }

}
