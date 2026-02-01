// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.security.KeyUsage;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public class KeySingleUsage {

  private final KeyUsage keyUsage;

  private final boolean required;

  public KeySingleUsage(KeyUsage keyUsage, boolean required) {
    this.keyUsage = Args.notNull(keyUsage, "keyUsage");
    this.required = required;
  }

  public KeyUsage keyUsage() {
    return keyUsage;
  }

  public boolean isRequired() {
    return required;
  }

}
