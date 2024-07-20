// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.xipki.util.exception.ObjectCreationException;

/**
 * Utility class for the reflective operations.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ReflectiveUtil {

  public static <T> T newInstance(String className) throws ObjectCreationException {
    return newInstance(className, null);
  }

  public static <T> T newInstance(String className, ClassLoader classLoader) throws ObjectCreationException {
    try {
      Class<?> clazz = (classLoader == null)
          ? Class.forName(className)
          : Class.forName(className, true, classLoader);
      return (T) clazz.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException ex) {
      throw new ObjectCreationException("create not create instance from " + className + ": " + ex.getMessage(), ex);
    } catch (ClassCastException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  }

}
