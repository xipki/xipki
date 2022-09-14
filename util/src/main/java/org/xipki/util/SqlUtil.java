/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.util;

/**
 * SQL utilities.
 *
 * @author Lijun Liao
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
