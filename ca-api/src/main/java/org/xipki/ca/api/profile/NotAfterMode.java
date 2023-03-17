// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.util.Args;

/**
 * How CA assigns the notAfter field in the certificate if the requested notAfter is
 * after CA's validity.
 * <ul>
 *  <li>STRICT: the enrollment request will be rejected.</li>
 *  <li>CUTOFF: Use CA's notAfter.</li>
 *  <li>BY_CA: CA decides.</li>
 * </ul>
 * @author Lijun Liao (xipki)
 */

public enum NotAfterMode {

  STRICT,
  CUTOFF,
  BY_CA;

  public static NotAfterMode forName(String text) {
    Args.notNull(text, "text");

    for (NotAfterMode value : values()) {
      if (value.name().equalsIgnoreCase(text)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid NotAfterMode " + text);
  }

}
