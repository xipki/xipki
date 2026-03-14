// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi reference policy.
 */
public enum ReferencePolicy {
  STATIC("static"),
  DYNAMIC("dynamic");

  private final String value;

  ReferencePolicy(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }
}
