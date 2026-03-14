// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi component configuration policy.
 */
public enum ConfigurationPolicy {
  OPTIONAL("optional"),
  REQUIRE("require"),
  IGNORE("ignore");

  private final String    value;

  ConfigurationPolicy(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }
}
