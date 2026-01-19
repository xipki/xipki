// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Extensions checker.
 *
 * @author Lijun Liao
 *
 */

public class CheckerUtil {

  public static <T> Set<T> elementInBnotInA(
      Collection<T> collectionA, Collection<T> collectionB) {
    if (collectionB == null) {
      return Collections.emptySet();
    }

    Set<T> result = new HashSet<>();
    for (T entry : collectionB) {
      if (collectionA == null || !collectionA.contains(entry)) {
        result.add(entry);
      }
    }
    return result;
  } // method strInBnotInA

  public static void addViolation(
      StringBuilder failureMsg, String field, Object is, Object expected) {
    failureMsg.append(field).append(" is '").append(is)
        .append("' but expected '").append(expected).append("';");
  } // method addViolation

}
