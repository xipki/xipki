// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.datasource;

import org.xipki.util.Args;

/**
 * Database type.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum DatabaseType {

  H2(false),
  DB2,
  HSQL,
  MYSQL,
  MARIADB,
  ORACLE,
  POSTGRES,
  UNKNOWN;

  private final boolean supportsInArray;

  DatabaseType() {
    this.supportsInArray = true;
  }

  DatabaseType(boolean supportsInArray) {
    this.supportsInArray = supportsInArray;
  }

  public boolean supportsInArray() {
    return supportsInArray;
  }

  public static DatabaseType forDriver(String driverClass) {
    return getDatabaseType(Args.notNull(driverClass, "driverClass"));
  }

  public static DatabaseType forDataSourceClass(String datasourceClass) {
    return getDatabaseType(Args.notNull(datasourceClass, "datasourceClass"));
  }

  public static DatabaseType forJdbcUrl(String url) {
    url = Args.notNull(url, "url").toLowerCase();
    if (url.startsWith("jdbc:db2")) {
      return DB2;
    } else if (url.startsWith("jdbc:h2")) {
      return H2;
    } else if (url.startsWith("jdbc:hsqldb")) {
      return HSQL;
    } else if (url.startsWith("jdbc:mysql")) {
      return MYSQL;
    } else if (url.startsWith("jdbc:mariadb")) {
      return MARIADB;
    } else if (url.startsWith("jdbc:oracle")) {
      return ORACLE;
    } else if (url.startsWith("jdbc:pgsql") || url.startsWith("jdbc:postgres") || url.startsWith("jdbc:postgresql")) {
      return POSTGRES;
    } else {
      return UNKNOWN;
    }
  }

  private static DatabaseType getDatabaseType(String className) {
    if (className.contains("db2.")) {
      return DatabaseType.DB2;
    } else if (className.contains("h2.")) {
      return DatabaseType.H2;
    } else if (className.contains("hsqldb.")) {
      return DatabaseType.HSQL;
    } else if (className.contains("mysql.")) {
      return DatabaseType.MYSQL;
    } else if (className.contains("mariadb.")) {
      return DatabaseType.MARIADB;
    } else if (className.contains("oracle.")) {
      return DatabaseType.ORACLE;
    } else if (className.contains("postgres.") || className.contains("postgresql.")) {
      return DatabaseType.POSTGRES;
    } else {
      return DatabaseType.UNKNOWN;
    }
  }

}
