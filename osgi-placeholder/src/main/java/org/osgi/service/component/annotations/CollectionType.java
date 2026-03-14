// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi reference collection type.
 */
public enum CollectionType {

  SERVICE("service"),
  REFERENCE("reference"),
  SERVICEOBJECTS("serviceobjects"),
  PROPERTIES("properties"),
  TUPLE("tuple");

  private final String value;

  CollectionType(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }

}
