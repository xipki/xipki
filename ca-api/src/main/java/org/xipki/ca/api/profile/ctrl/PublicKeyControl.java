// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.security.KeySpec;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class PublicKeyControl {
  private final List<KeySpec> algorithms;

  public PublicKeyControl(List<KeySpec> keySpecs) {
    this.algorithms = keySpecs == null || keySpecs.isEmpty()
        ? null : List.copyOf(keySpecs);
  }

  public boolean allowsPublicKey(KeySpec keySpec) {
    if (algorithms == null) return true;
    return algorithms.contains(keySpec);
  }

}
