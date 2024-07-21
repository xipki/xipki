// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

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
  BY_CA

}
