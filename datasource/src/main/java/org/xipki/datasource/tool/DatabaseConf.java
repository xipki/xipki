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
package org.xipki.datasource.tool;

import org.xipki.password.*;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.util.Properties;

import static org.xipki.util.Args.notNull;

/**
 * Database configuration.
 * @author Lijun Liao
 */
public class DatabaseConf {

  private final String type;

  private final String driver;

  private final String username;

  private final String password;

  private final String url;

  private final String schema;

  public DatabaseConf(String driver, String username, String password, String url, String schema) {
    this.driver = driver;
    this.username = notNull(username, "username");
    this.password = password;
    this.url = notNull(url, "url");
    this.schema = schema;

    if (driver.contains("org.h2.")) {
      this.type = "h2";
    } else if (driver.contains("mysql.") || driver.contains("mariadb.")) {
      this.type = "mysql";
    } else if (driver.contains("oracle.")) {
      this.type = "oracle";
    } else if (driver.contains("db2.")) {
      this.type = "db2";
    } else if (driver.contains("postgresql.") || driver.contains("postgres.")) {
      this.type = "postgresql";
    } else if (driver.contains("hsqldb.")) {
      this.type = "hsqldb";
    } else {
      this.type = "unknown";
    }
  }

  public String getType() {
    return type;
  }

  public String getDriver() {
    return driver;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public String getUrl() {
    return url;
  }

  public String getSchema() {
    return schema;
  }

  public static DatabaseConf getInstance(Properties dbProps, PasswordResolver passwordResolver)
      throws PasswordResolverException {
    notNull(dbProps, "dbProps");

    String schema = dbProps.getProperty("sqlscript.schema");
    if (schema == null) {
      schema = dbProps.getProperty("liquibase.schema");
    }

    if (schema != null) {
      schema = schema.trim();
      if (schema.isEmpty()) {
        schema = null;
      }
    }

    String user = dbProps.getProperty("dataSource.user");
    if (user == null) {
      user = dbProps.getProperty("username");
    }

    String password = dbProps.getProperty("dataSource.password");
    if (password == null) {
      password = dbProps.getProperty("password");
    }

    if (passwordResolver != null && (password != null && !password.isEmpty())) {
      password = new String(passwordResolver.resolvePassword(password));
    }

    String url = dbProps.getProperty("jdbcUrl");
    if (url != null) {
      String driverClassName = dbProps.getProperty("driverClassName");
      if (driverClassName == null) {
        if (url.startsWith("jdbc:h2:")) {
          driverClassName = "org.h2.Driver";
        } else if (url.startsWith("jdbc:mysql:")) {
          driverClassName = "com.mysql.jdbc.Driver";
        } else if (url.startsWith("jdbc:mariadb:")) {
          driverClassName = "org.mariadb.jdbc.Driver";
        } else if (url.startsWith("jdbc:oracle:")) {
          driverClassName = "oracle.jdbc.driver.OracleDriver";
        } else if (url.startsWith("jdbc:db2:")) {
          driverClassName = "com.ibm.db2.jcc.DB2Driver";
        } else if (url.startsWith("jdbc:postgresql:") || url.startsWith("jdbc:pgsql:")) {
          driverClassName = "org.postgresql.Driver";
        } else if (url.startsWith("jdbc:hsqldb:")) {
          driverClassName = "org.hsqldb.jdbc.JDBCDriver";
        } else {
          throw new IllegalArgumentException("unknown jdbc database URL " + url + ", please specify driverClassName");
        }
      }
      return new DatabaseConf(driverClassName, user, password, url, schema);
    }

    String datasourceClassName = dbProps.getProperty("dataSourceClassName");
    if (datasourceClassName == null) {
      throw new IllegalArgumentException("unsupported configuration");
    }

    StringBuilder urlBuilder = new StringBuilder();

    datasourceClassName = datasourceClassName.toLowerCase();
    String driverClassName;

    if (datasourceClassName.contains("org.h2.")) {
      driverClassName = "org.h2.Driver";
      String dataSourceUrl = dbProps.getProperty("dataSource.url");
      String prefix = "jdbc:h2:";
      if (dataSourceUrl.startsWith(prefix + "~")) {
        urlBuilder.append(prefix).append(IoUtil.expandFilepath(dataSourceUrl.substring(prefix.length())));
      } else {
        urlBuilder.append(dataSourceUrl);
      }

      if (schema != null) {
        urlBuilder.append(";INIT=CREATE SCHEMA IF NOT EXISTS ").append(schema);
      }
    } else if (datasourceClassName.contains("mysql.")) {
      driverClassName = "com.mysql.jdbc.Driver";
      urlBuilder.append("jdbc:mysql://")
          .append(dbProps.getProperty("dataSource.serverName")).append(":")
          .append(dbProps.getProperty("dataSource.port")).append("/")
          .append(dbProps.getProperty("dataSource.databaseName"));
    } else if (datasourceClassName.contains("mariadb.")) {
      driverClassName = "org.mariadb.jdbc.Driver";
      String str = dbProps.getProperty("dataSource.url");
      if (StringUtil.isNotBlank(str)) {
        urlBuilder.append(str);
      } else {
        urlBuilder.append("jdbc:mariadb://")
            .append(dbProps.getProperty("dataSource.serverName")).append(":")
            .append(dbProps.getProperty("dataSource.port")).append("/")
            .append(dbProps.getProperty("dataSource.databaseName"));
      }
    } else if (datasourceClassName.contains("oracle.")) {
      driverClassName = "oracle.jdbc.driver.OracleDriver";
      String str = dbProps.getProperty("dataSource.URL");
      if (StringUtil.isNotBlank(str)) {
        urlBuilder.append(str);
      } else {
        urlBuilder.append("jdbc:oracle:thin:@")
            .append(dbProps.getProperty("dataSource.serverName")).append(":")
            .append(dbProps.getProperty("dataSource.portNumber")).append(":")
            .append(dbProps.getProperty("dataSource.databaseName"));
      }
    } else if (datasourceClassName.contains("com.ibm.db2.")) {
      driverClassName = "com.ibm.db2.jcc.DB2Driver";
      schema = dbProps.getProperty("dataSource.currentSchema");

      urlBuilder.append("jdbc:db2://")
          .append(dbProps.getProperty("dataSource.serverName")).append(":")
          .append(dbProps.getProperty("dataSource.portNumber")).append("/")
          .append(dbProps.getProperty("dataSource.databaseName"));
    } else if (datasourceClassName.contains("postgresql.")
        || datasourceClassName.contains("impossibl.postgres.")) {
      String serverName;
      String portNumber;
      String databaseName;
      if (datasourceClassName.contains("postgresql.")) {
        serverName = dbProps.getProperty("dataSource.serverName");
        portNumber = dbProps.getProperty("dataSource.portNumber");
        databaseName = dbProps.getProperty("dataSource.databaseName");
      } else {
        serverName = dbProps.getProperty("dataSource.host");
        portNumber = dbProps.getProperty("dataSource.port");
        databaseName = dbProps.getProperty("dataSource.database");
      }
      driverClassName = "org.postgresql.Driver";
      urlBuilder.append("jdbc:postgresql://")
          .append(serverName).append(":").append(portNumber).append("/").append(databaseName);
    } else if (datasourceClassName.contains("hsqldb.")) {
      driverClassName = "org.hsqldb.jdbc.JDBCDriver";
      String dataSourceUrl = dbProps.getProperty("dataSource.url");
      String prefix = "jdbc:hsqldb:file:";
      if (dataSourceUrl.startsWith(prefix + "~")) {
        urlBuilder.append(prefix).append(IoUtil.expandFilepath(dataSourceUrl.substring(prefix.length())));
      } else {
        urlBuilder.append(dataSourceUrl);
      }
    } else {
      throw new IllegalArgumentException("unsupported database type " + datasourceClassName);
    }

    url = urlBuilder.toString();

    if (password != null) {
      char[] newPassword = null;
      if (StringUtil.startsWithIgnoreCase(password, OBFPasswordService.PROTOCOL_OBF + ":")) {
        SinglePasswordResolver.OBF resolver = new SinglePasswordResolver.OBF();
        newPassword = resolver.resolvePassword(password);
      } else if (StringUtil.startsWithIgnoreCase(password, PBEPasswordService.PROTOCOL_PBE + ":")) {
        char[] masterPassword = IoUtil.readPasswordFromConsole("Enter the master password");
        newPassword = PBEPasswordService.decryptPassword(masterPassword, password);
      }

      if (newPassword != null) {
        password = new String(newPassword);
      }
    }

    return new DatabaseConf(driverClassName, user, password, url, schema);
  } // method getInstance

}
