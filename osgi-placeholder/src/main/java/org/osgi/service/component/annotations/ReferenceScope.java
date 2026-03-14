// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi reference scope.
 */
public enum ReferenceScope {
  BUNDLE("bundle"),
  PROTOTYPE("prototype"),
  PROTOTYPE_REQUIRED("prototype_required");

  private final String value;

  ReferenceScope(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }
}
