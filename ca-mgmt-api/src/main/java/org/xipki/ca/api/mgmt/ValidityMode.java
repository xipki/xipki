// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.Args;

/**
 * How CA assigns the notAfter field in the certificate if the requested notAfter is
 * after CA's validity.
 * <ul>
 *  <li>STRICT: the enrollment request will be rejected.</li>
 *  <li>LAX: Use the requested notAfter.</li>
 *  <li>CUTOFF: Use CA's notAfter.</li>
 * </ul>
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum ValidityMode {

  strict,
  lax,
  cutoff;

  public static ValidityMode forName(String text) {
    Args.notNull(text, "text");

    for (ValidityMode value : values()) {
      if (value.name().equalsIgnoreCase(text)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid ValidityMode " + text);
  }

}
