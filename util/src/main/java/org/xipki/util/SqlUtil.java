// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

/**
 * SQL utilities.
 *
 * @author Lijun Liao (xipki)
 */
public class SqlUtil {

  public static String buildInsertSql(String table, String columns) {
    int numTokens = 1;
    for (int i = 1; i < columns.length(); i++) {
      if (columns.charAt(i) == ',') {
        numTokens++;
      }
    }

    StringBuilder sb = new StringBuilder(100);
    sb.append("INSERT INTO ").append(table).append(" (").append(columns).append(") VALUES(");
    for (int i = 0; i < numTokens; i++) {
      sb.append('?');
      if (i != numTokens - 1) {
        sb.append(",");
      }
    }

    sb.append(")");
    return sb.toString();
  }

}
