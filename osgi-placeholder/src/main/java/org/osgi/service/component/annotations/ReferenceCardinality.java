// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi reference cardinality.
 */
public enum ReferenceCardinality {
  OPTIONAL("0..1"),
  MANDATORY("1..1"),
  MULTIPLE("0..n"),
  AT_LEAST_ONE("1..n");

  private final String value;

  ReferenceCardinality(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }
}
