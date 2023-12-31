// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.exception.InvalidConfException;

import java.util.Collection;

/**
 * Container of permissions.
 *
 * @author Lijun Liao (xipki)
 */
public class Permissions {

  private final int value;

  public Permissions(int value) {
    this.value = value;
  }

  public Permissions(Collection<String> texts) throws InvalidConfException {
    this.value = PermissionConstants.toIntPermission(texts);
  }

  public boolean isPermitted(int permission) {
    return PermissionConstants.contains(value, permission);
  }

  @Override
  public int hashCode() {
    return value;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof Permissions)) {
      return false;
    }

    return value == ((Permissions) obj).value;
  }

  @Override
  public String toString() {
    return PermissionConstants.permissionToString(value);
  }

  public int getValue() {
    return value;
  }

}
