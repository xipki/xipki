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

import java.io.Closeable;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.IoUtil;
import org.xipki.util.Args;

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

/**
 * Class for executing Liquibase via the command line.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class LiquibaseMain implements Closeable {

  private static Logger LOG = LoggerFactory.getLogger(LiquibaseMain.class);

  private final LiquibaseDatabaseConf dbConf;

  private final String changeLogFile;

  private Database database;

  private Liquibase liquibase;

  public LiquibaseMain(LiquibaseDatabaseConf dbConf, String changeLogFile) {
    this.dbConf = Args.notNull(dbConf, "dbConf");
    this.changeLogFile = IoUtil.expandFilepath(Args.notBlank(changeLogFile, "changeLogFile"));
  }

  public void init() throws Exception {

    ResourceAccessor fsOpener = new FileSystemResourceAccessor() {
      @Override
      protected void addRootPath(URL path) {
        try {
          new File(path.toURI());
        } catch (URISyntaxException e) {
          //add like normal
        } catch (IllegalArgumentException e) {
          // this line is added to avoid the IllegalArgumentException: URI is not
          // hierarchical in java 10+.
          return;
        }

        super.addRootPath(path);
      }
    };

    ClassLoader classLoader = getClass().getClassLoader();
    ResourceAccessor clOpener = new CommandLineResourceAccessor(classLoader);

    String defaultSchemaName = dbConf.getSchema();
    this.database = CommandLineUtils.createDatabaseObject(clOpener, // resourceAccessor
      dbConf.getUrl(), dbConf.getUsername(), dbConf.getPassword(), dbConf.getDriver(),
      (String) null, // defaultCatalogName
      defaultSchemaName, // defaultSchemaName
      false, // outputDefaultCatalog
      false, // outputDefaultSchema
      (String) null, // databaseClass
      (String) null, // driverPropertiesFile
      (String) null, // propertyProviderClass
      (String) null, // liquibaseCatalogName
      (String) null, // liquibaseSchemaName
      (String) null, // databaseChangeLogTableName
      (String) null); // databaseChangeLogLockTableName

    try {
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

  public void releaseLocks() throws Exception {
    LockService lockService = LockServiceFactory.getInstance().getLockService(database);
    lockService.forceReleaseLock();
    System.out.println("successfully released the database");
  }

  public void dropAll() throws Exception {
    liquibase.dropAll();
    System.out.println("successfully  dropped the database");
  }

  public void update() throws Exception {
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
  }

  public static boolean loglevelIsSevereOrOff(String logLevel) {
    return "off".equalsIgnoreCase(logLevel) || "severe".equalsIgnoreCase(logLevel);
  }

}
