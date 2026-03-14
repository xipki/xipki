// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

/**
 * Placeholder enum for OSGi provided service scope.
 */
public enum ServiceScope {

  SINGLETON("singleton"),
  BUNDLE("bundle"),
  PROTOTYPE("prototype"),
  DEFAULT("<<default>>");

  private final String value;

  ServiceScope(String value) {
      this.value = value;
  }

  @Override
  public String toString() {
      return value;
  }
}
