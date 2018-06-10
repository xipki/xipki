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

package org.xipki.dbtool;

import java.util.Objects;
import java.util.Properties;

import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class LiquibaseDatabaseConf {

  private final String driver;

  private final String username;

  private final String password;

  private final String url;

  private final String schema;

  private LiquibaseDatabaseConf(String driver, String username, String password,
      String url, String schema) {
    this.driver = driver;
    this.username = Objects.requireNonNull(username, "username must not be null");
    this.password = password;
    this.url = Objects.requireNonNull(url, "url must not be null");
    this.schema = schema;
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

  public static LiquibaseDatabaseConf getInstance(Properties dbProps,
      PasswordResolver passwordResolver) throws PasswordResolverException {
    ParamUtil.requireNonNull("dbProps", dbProps);

    String schema = dbProps.getProperty("liquibase.schema");
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
      return new LiquibaseDatabaseConf(driverClassName, user, password, url, schema);
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
      urlBuilder.append(dbProps.getProperty("dataSource.url"));
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
      String str = dbProps.getProperty("dataSource.URL");
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
      urlBuilder.append(dbProps.getProperty("dataSource.url"));
    } else {
      throw new IllegalArgumentException("unsupported database type " + datasourceClassName);
    }

    url = urlBuilder.toString();

    return new LiquibaseDatabaseConf(driverClassName, user, password, url, schema);
  } // method getInstance

}
