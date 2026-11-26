// License Apache License 2.0

package org.xipki.mgmt.web.core;

/**
 * @author palos
 */
public final class AccessDeniedException extends ApiException {
  public AccessDeniedException(String message) {
    super(403, message);
  }
}
