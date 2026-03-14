// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi reference policy options.
 */
public enum ReferencePolicyOption {
  RELUCTANT("reluctant"),
  GREEDY("greedy");

  private final String value;

  ReferencePolicyOption(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }
}
