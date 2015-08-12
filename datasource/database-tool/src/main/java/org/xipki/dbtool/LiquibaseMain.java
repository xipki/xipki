/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.dbtool;

import liquibase.CatalogAndSchema;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.diff.compare.CompareControl;
import liquibase.diff.output.DiffOutputControl;
import liquibase.exception.CommandLineParsingException;
import liquibase.exception.DatabaseException;
import liquibase.integration.commandline.CommandLineResourceAccessor;
import liquibase.integration.commandline.CommandLineUtils;
import liquibase.lockservice.LockService;
import liquibase.lockservice.LockServiceFactory;
import liquibase.logging.LogFactory;
import liquibase.resource.CompositeResourceAccessor;
import liquibase.resource.FileSystemResourceAccessor;

/**
 * Class for executing Liquibase via the command line.
 *
 * @author Lijun Liao
 */

public class LiquibaseMain
{
    private final LiquibaseDatabaseConf dbConf;
    private final String changeLogFile;

    private Database database;
    private Liquibase liquibase;

    public static boolean loglevelIsSevereOrOff(
            final String logLevel)
    {
        return "off".equalsIgnoreCase(logLevel) || "severe".equalsIgnoreCase(logLevel);
    }

    public LiquibaseMain(
            final LiquibaseDatabaseConf dbConf,
            final String changeLogFile)
    {
        if(dbConf == null)
        {
            throw new IllegalArgumentException("dbConf could not be null");
        }

        if(MyStringUtil.isBlank(changeLogFile))
        {
            throw new IllegalArgumentException("changeLogFile could not be empty");
        }

        this.dbConf = dbConf;
        this.changeLogFile = changeLogFile;
    }

    public void changeLogLevel(
            final String logLevel)
    throws CommandLineParsingException
    {
        try
        {
            LogFactory.getInstance().getLog().setLogLevel(logLevel);
        } catch (IllegalArgumentException e)
        {
            throw new CommandLineParsingException(e.getMessage(), e);
        }
    }

    public void init(
            final String logLevel)
    throws Exception
    {
        changeLogLevel(logLevel);

        FileSystemResourceAccessor fsOpener = new FileSystemResourceAccessor();
        ClassLoader classLoader = getClass().getClassLoader();
        CommandLineResourceAccessor clOpener = new CommandLineResourceAccessor(classLoader);

        String defaultSchemaName = dbConf.getSchema();
        this.database = CommandLineUtils.createDatabaseObject(
            classLoader, // classLoader
            dbConf.getUrl(), // url
            dbConf.getUsername(), // username
            dbConf.getPassword(), // password
            dbConf.getDriver(), // driver
            (String) null, // defaultCatalogName
            defaultSchemaName,// defaultSchemaName
            false, // outputDefaultCatalog
            false, // outputDefaultSchema
            (String) null, // databaseClass
            (String) null, // driverPropertiesFile
            (String) null, // liquibaseCatalogName
            (String) null); //liquibaseSchemaName

        try
        {
            CompositeResourceAccessor fileOpener = new CompositeResourceAccessor(fsOpener, clOpener);

            boolean includeCatalog = false;
            boolean includeSchema = false;
            boolean includeTablespace = false;
            DiffOutputControl diffOutputControl = new DiffOutputControl(includeCatalog, includeSchema, includeTablespace);

            CompareControl.SchemaComparison[] finalSchemaComparisons;
            finalSchemaComparisons = new CompareControl.SchemaComparison[]
                    {
                        new CompareControl.SchemaComparison(
                            new CatalogAndSchema(null, defaultSchemaName),
                            new CatalogAndSchema(null, defaultSchemaName))
                    };

            for (CompareControl.SchemaComparison schema : finalSchemaComparisons)
            {
                diffOutputControl.addIncludedSchema(schema.getReferenceSchema());
                diffOutputControl.addIncludedSchema(schema.getComparisonSchema());
            }

            this.liquibase = new Liquibase(changeLogFile, fileOpener, database);
        } catch(Exception e)
        {
            try
            {
                database.rollback();
                database.close();
            } catch (Exception e2)
            {
                LogFactory.getInstance().getLog().warning("problem closing connection", e);
            }
            throw e;
        }

    }

    public void releaseLocks()
    throws Exception
    {
        LockService lockService = LockServiceFactory.getInstance().getLockService(database);
        lockService.forceReleaseLock();
        System.out.println("successfully released the database");
    }

    public void dropAll()
    throws Exception
    {
        liquibase.dropAll();
        System.out.println("successfully  dropped the database");
    }

    public void update()
    throws Exception
    {
        liquibase.update((String) null);
        System.out.println("successfully  updated the database");
    }

    public void shutdown()
    {
        try
        {
            if(database != null)
            {
                database.rollback();
                database.close();
            }
        } catch (DatabaseException e)
        {
            LogFactory.getInstance().getLog().warning("problem closing connection", e);
        } finally
        {
            database = null;
            liquibase = null;
        }
    }
}
