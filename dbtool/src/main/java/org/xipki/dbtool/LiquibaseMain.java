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

package org.xipki.dbtool;

import liquibase.CatalogAndSchema;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.diff.compare.CompareControl;
import liquibase.diff.output.DiffOutputControl;
import liquibase.exception.DatabaseException;
import liquibase.integration.commandline.CommandLineResourceAccessor;
import liquibase.integration.commandline.CommandLineUtils;
import liquibase.lockservice.LockService;
import liquibase.lockservice.LockServiceFactory;
import liquibase.resource.CompositeResourceAccessor;
import liquibase.resource.FileSystemResourceAccessor;
import liquibase.resource.ResourceAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PBEPasswordService;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.password.SinglePasswordResolver;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.Closeable;
import java.io.File;
import java.util.Properties;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Class for executing Liquibase via the command line.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class LiquibaseMain implements Closeable {

  public static class DatabaseConf {

    private final String driver;

    private final String username;

    private final String password;

    private final String url;

    private final String schema;

    public DatabaseConf(String driver, String username, String password,
        String url, String schema) {
      this.driver = driver;
      this.username = notNull(username, "username");
      this.password = password;
      this.url = notNull(url, "url");
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

    public static DatabaseConf getInstance(Properties dbProps, PasswordResolver passwordResolver)
        throws PasswordResolverException {
      notNull(dbProps, "dbProps");

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
          urlBuilder.append(prefix)
            .append(IoUtil.expandFilepath(dataSourceUrl.substring(prefix.length())));
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
          urlBuilder.append(prefix)
            .append(IoUtil.expandFilepath(dataSourceUrl.substring(prefix.length())));
        } else {
          urlBuilder.append(dataSourceUrl);
        }
      } else {
        throw new IllegalArgumentException("unsupported database type " + datasourceClassName);
      }

      url = urlBuilder.toString();

      if (password != null) {
        char[] newPassword = null;
        if (StringUtil.startsWithIgnoreCase(password, "OBF:")) {
          SinglePasswordResolver.OBF resolver = new SinglePasswordResolver.OBF();
          newPassword = resolver.resolvePassword(password);
        } else if (StringUtil.startsWithIgnoreCase(password, "PBE:")) {
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

  private static class MyFileSystemResourceAccessor extends FileSystemResourceAccessor {
    public void addWorkingDir() {
      super.addRootPath(new File(".").getAbsoluteFile().toPath());
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(LiquibaseMain.class);

  private final DatabaseConf dbConf;

  private final String changeLogFile;

  private Database database;

  private Liquibase liquibase;

  public LiquibaseMain(DatabaseConf dbConf, String changeLogFile) {
    this.dbConf = notNull(dbConf, "dbConf");
    this.changeLogFile = IoUtil.expandFilepath(notBlank(changeLogFile, "changeLogFile"));
  }

  public void init()
      throws Exception {
    org.tinylog.jul.JulTinylogBridge.activate();

    ClassLoader classLoader = getClass().getClassLoader();
    ResourceAccessor clOpener = new CommandLineResourceAccessor(classLoader);

    String defaultSchemaName = dbConf.getSchema();
    this.database = CommandLineUtils.createDatabaseObject(clOpener, // resourceAccessor
      dbConf.getUrl(), dbConf.getUsername(), dbConf.getPassword(), dbConf.getDriver(),
      null, // defaultCatalogName
      defaultSchemaName, // defaultSchemaName
      false, // outputDefaultCatalog
      false, // outputDefaultSchema
      null, // databaseClass
      null, // driverPropertiesFile
      null, // propertyProviderClass
      null, // liquibaseCatalogName
      null, // liquibaseSchemaName
      null, // databaseChangeLogTableName
      null); // databaseChangeLogLockTableName

    try {
      MyFileSystemResourceAccessor fsOpener = new MyFileSystemResourceAccessor();
      fsOpener.addWorkingDir();

      CompositeResourceAccessor fileOpener = new CompositeResourceAccessor(fsOpener, clOpener);

      DiffOutputControl diffOutputControl = new DiffOutputControl(false, // includeCatalog
          false, // includeSchema
          false, // includeTablespace
          null); // schemaComparisons

      CompareControl.SchemaComparison[] finalSchemaComparisons;
      finalSchemaComparisons = new CompareControl.SchemaComparison[] {
        new CompareControl.SchemaComparison(new CatalogAndSchema(null, defaultSchemaName),
            new CatalogAndSchema(null, defaultSchemaName))};

      for (CompareControl.SchemaComparison schema : finalSchemaComparisons) {
        diffOutputControl.addIncludedSchema(schema.getReferenceSchema());
        diffOutputControl.addIncludedSchema(schema.getComparisonSchema());
      }

      this.liquibase = new Liquibase(changeLogFile, fileOpener, database);
    } catch (Exception ex) {
      try {
        database.rollback();
        database.close();
      } catch (Exception ex2) {
        LOG.warn("problem closing connection", ex2);
      }
      throw ex;
    }
  } // method init

  public void releaseLocks()
      throws Exception {
    LockService lockService = LockServiceFactory.getInstance().getLockService(database);
    lockService.forceReleaseLock();
    System.out.println("successfully released the database");
  }

  public void dropAll()
      throws Exception {
    liquibase.dropAll();
    System.out.println("successfully  dropped the database");
  }

  public void update()
      throws Exception {
    liquibase.update((String) null);
    System.out.println("successfully  updated the database");
  }

  @Override
  public void close() {
    try {
      if (database != null) {
        database.rollback();
        database.close();
      }
    } catch (DatabaseException ex) {
      LOG.warn("problem closing connection", ex);
    } finally {
      database = null;
      liquibase = null;
    }
  } // method close

  public static boolean loglevelIsSevereOrOff(String logLevel) {
    return "off".equalsIgnoreCase(logLevel) || "severe".equalsIgnoreCase(logLevel);
  }

}
