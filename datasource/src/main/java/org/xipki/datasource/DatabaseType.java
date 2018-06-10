/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.datasource;

import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum DatabaseType {

  H2,
  DB2,
  HSQL,
  MYSQL,
  MARIADB,
  ORACLE,
  POSTGRES,
  UNKNOWN;

  public static DatabaseType forDriver(String driverClass) {
    ParamUtil.requireNonNull("driverClass", driverClass);
    return getDatabaseType(driverClass);
  }

  public static DatabaseType forDataSourceClass(String datasourceClass) {
    ParamUtil.requireNonNull("datasourceClass", datasourceClass);
    return getDatabaseType(datasourceClass);
  }

  public static DatabaseType forJdbcUrl(String url) {
    ParamUtil.requireNonNull("url", url);
    url = url.toLowerCase();
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
    } else if (url.startsWith("jdbc:pgsql") || url.startsWith("jdbc:postgres")
        || url.startsWith("jdbc:postgresql")) {
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
