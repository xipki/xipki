// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi field update options.
 */
public enum FieldOption {

  UPDATE("update"),
  REPLACE("replace");

  private final String    value;

  FieldOption(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }
}
