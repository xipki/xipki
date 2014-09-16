/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.liquibase;

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

    public static boolean loglevelIsSevereOrOff(String logLevel)
    {
        return "off".equalsIgnoreCase(logLevel) || "severe".equalsIgnoreCase(logLevel);
    }

    public LiquibaseMain(LiquibaseDatabaseConf dbConf, String changeLogFile)
    {
        if(dbConf == null)
        {
            throw new IllegalArgumentException("dbConf could not be null");
        }

        if(changeLogFile == null || changeLogFile.isEmpty())
        {
            throw new IllegalArgumentException("changeLogFile could not be empty");
        }

        this.dbConf = dbConf;
        this.changeLogFile = changeLogFile;
    }

    public void changeLogLevel(String logLevel)
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

    public void init(String logLevel)
    throws Exception
    {
        changeLogLevel(logLevel);

        FileSystemResourceAccessor fsOpener = new FileSystemResourceAccessor();
        ClassLoader classLoader = getClass().getClassLoader();
        CommandLineResourceAccessor clOpener = new CommandLineResourceAccessor(classLoader);

        String defaultSchemaName = dbConf.getSchema();
        this.database = CommandLineUtils.createDatabaseObject(classLoader,
            dbConf.getUrl(), dbConf.getUsername(), dbConf.getPassword(), dbConf.getDriver(),
            null, defaultSchemaName,
            false, false, null, null, null, null);

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
        System.out.println("Successfully released the database");
    }

    public void dropAll()
    throws Exception
    {
        liquibase.dropAll();
        System.out.println("Successfully dropped the database");
    }

    public void update()
    throws Exception
    {
        liquibase.update((String) null);
        System.out.println("Successfully updated the database");
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
