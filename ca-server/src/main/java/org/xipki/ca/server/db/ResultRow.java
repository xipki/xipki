/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.server.db;

import java.math.BigDecimal;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Result Row.
 * @author Lijun Liao
 *
 */
class ResultRow {

  private final Map<String, Object> columns = new HashMap<>();

  ResultRow(ResultSet rs) throws SQLException {
    ResultSetMetaData metaData = rs.getMetaData();
    int count = metaData.getColumnCount();

    for (int index = 1; index <= count; index++) {
      String label = metaData.getColumnLabel(index);
      int itype = metaData.getColumnType(index);

      Object value;
      switch (itype) {
        case Types.BOOLEAN:
        case Types.BIT:
          value = rs.getBoolean(index);
          break;
        case Types.TINYINT:
        case Types.SMALLINT:
        case Types.INTEGER:
          value = rs.getInt(index);
          break;
        case Types.BIGINT:
          value = rs.getLong(index);
          break;
        case Types.CHAR:
        case Types.VARCHAR:
        case Types.LONGVARCHAR:
        case Types.NCHAR:
        case Types.NVARCHAR:
        case Types.LONGNVARCHAR:
          value = rs.getString(index);
          break;
        case Types.CLOB:
        case Types.NCLOB:
          Clob clob = rs.getClob(index);
          value = clob == null ? null : clob.getSubString(1, (int) clob.length());
          break;
        case Types.TIMESTAMP:
        case Types.TIMESTAMP_WITH_TIMEZONE:
          value = rs.getTimestamp(index);
          break;
        case Types.DATE:
          value = rs.getDate(index);
          break;
        case Types.TIME:
          value = rs.getTime(index);
          break;
        case Types.REAL:
          value = rs.getFloat(index);
          break;
        case Types.FLOAT:
        case Types.DOUBLE:
          value = rs.getDouble(index);
          break;
        case Types.NUMERIC:
        case Types.DECIMAL:
          value = rs.getBigDecimal(index);
          break;
        case Types.BINARY:
        case Types.VARBINARY:
        case Types.LONGVARBINARY:
          value = rs.getBytes(index);
          break;
        case Types.BLOB:
          Blob blob = rs.getBlob(index);
          value = blob == null ? null : blob.getBytes(1, (int) blob.length());
          break;
        default:
          throw new SQLException("unknown data type " + itype);
      }

      columns.put(label.toUpperCase(), value);
    }
  }

  int getInt(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return 0;
    }

    if (obj instanceof Integer) {
      return (int) obj;
    } else if (obj instanceof Long) {
      return (int) ((long) obj);
    } else if (obj instanceof Boolean) {
      return ((boolean) obj) ? 1 : 0;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to int");
    }
  }

  boolean getBoolean(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return false;
    }

    if (obj instanceof Boolean) {
      return (boolean) obj;
    } else if (obj instanceof Integer) {
      return ((int) obj) != 0;
    } else if (obj instanceof Long) {
      return ((long) obj) != 0;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to boolean");
    }
  }

  long getLong(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return 0;
    }

    if (obj instanceof Long) {
      return (long) obj;
    } else if (obj instanceof Integer) {
      return (long) ((int) obj);
    } else if (obj instanceof Boolean) {
      return ((boolean) obj) ? 1 : 0;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to long");
    }
  }

  String getString(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return null;
    }

    if (obj instanceof Boolean) {
      return ((boolean) obj) ? "TRUE" : "FALSE";
    } else if (obj instanceof String) {
      return (String) obj;
    } else {
      return obj.toString();
    }
  }

  Timestamp getTimestamp(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return null;
    }

    if (obj instanceof Timestamp) {
      return (Timestamp) obj;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to Timestamp");
    }
  }

  byte[] getBytes(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return null;
    }

    if (obj instanceof byte[]) {
      return (byte[]) obj;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to byte[]");
    }
  }

  Time getTime(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return null;
    }

    if (obj instanceof Time) {
      return (Time) obj;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to Time");
    }
  }

  Date getDate(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return null;
    }

    if (obj instanceof Date) {
      return (Date) obj;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to Date");
    }
  }

  float getFloat(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return 0;
    }

    if (obj instanceof Float) {
      return (float) obj;
    } else if (obj instanceof Double) {
      return (float) ((double) obj);
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to float");
    }
  }

  double getDouble(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return 0;
    }

    if (obj instanceof Double) {
      return (double) obj;
    } else if (obj instanceof Float) {
      return (double) ((float) obj);
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to double");
    }
  }

  BigDecimal getBigDecimal(String label) {
    Object obj = columns.get(label.toUpperCase());
    if (obj == null) {
      return null;
    }

    if (obj instanceof BigDecimal) {
      return (BigDecimal) obj;
    } else {
      throw new IllegalArgumentException(
          "cannot convert " + obj.getClass().getName() + " to BigDecimal");
    }
  }

}
