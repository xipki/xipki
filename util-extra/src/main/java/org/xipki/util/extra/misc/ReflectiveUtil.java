// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.misc;

import org.xipki.util.extra.exception.ObjectCreationException;

/**
 * Utility class for the reflective operations.
 *
 * @author Lijun Liao (xipki)
 */

public class ReflectiveUtil {

  public static <T> T newInstance(String className)
      throws ObjectCreationException {
    return newInstance(className, null);
  }

  public static <T> T newInstance(String className, ClassLoader classLoader)
      throws ObjectCreationException {
    try {
      Class<?> clazz = (classLoader == null)
          ? Class.forName(className)
          : Class.forName(className, true, classLoader);
      return (T) clazz.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException ex) {
      throw new ObjectCreationException("create not create instance from "
          + className + ": " + ex.getMessage(), ex);
    } catch (ClassCastException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  }

}
