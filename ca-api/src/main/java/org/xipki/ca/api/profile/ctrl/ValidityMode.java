// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.ctrl;

import org.xipki.util.codec.Args;

/**
 * How CA assigns the notAfter field in the certificate if the requested
 * notAfter is after CA's validity.
 * <ul>
 *  <li>STRICT: the enrollment request will be rejected.</li>
 *  <li>CUTOFF: Use CA's notAfter.</li>
 *  <li>BY_CA:  by CA.</li>
 * </ul>
 * @author Lijun Liao (xipki)
 *
 */
public enum ValidityMode {

  STRICT,
  CUTOFF,
  BY_CA;

  public static ValidityMode forName(String text) {
    Args.notNull(text, "text");

    if ("LAX".equalsIgnoreCase(text) // historic reason
        || "BY-CA".equalsIgnoreCase(text)
        || "BYCA".equalsIgnoreCase(text)) {
      return BY_CA;
    }

    for (ValidityMode value : values()) {
      if (value.name().equalsIgnoreCase(text)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid ValidityMode " + text);
  }

}
