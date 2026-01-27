// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.conf.InvalidConfException;

import java.util.Collection;
import java.util.List;

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

  public static Permissions parseJson(Object obj) throws CodecException {
    if (obj instanceof JsonList) {
      return parse((JsonList) obj);
    } else if (obj instanceof Long) {
      return new Permissions((int) (long) obj);
    } else if (obj instanceof Integer) {
      return new Permissions((int) obj);
    } else {
      throw new CodecException("unknown obj " + obj.getClass().getName());
    }
  }

  public static Permissions parse(JsonList json) throws CodecException {
    try {
      return new Permissions(json.toStringList());
    } catch (InvalidConfException e) {
      throw new CodecException(e);
    }
  }

  public List<String> toPermissionTexts() {
    return PermissionConstants.permissionToStringList(value);
  }

}
