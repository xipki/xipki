/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import liquibase.exception.CommandLineParsingException;
import liquibase.exception.LiquibaseException;
import liquibase.integration.commandline.Main;

import org.xipki.database.api.SimpleDatabaseConf;
import org.xipki.security.common.IoCertUtil;

/**
 *
 * @author Lijun Liao
 */

public class LiquibaseCommandLine extends Main
{
    public static void releaseLocks(SimpleDatabaseConf dbParams, String logLevel)
    throws LiquibaseException, CommandLineParsingException, IOException
    {
        if(logLevel != null && "severe".equals(logLevel) == false)
        {
            logLevel = "severe";
        }
        String[] args = createCommandLineArgments("releaseLocks", dbParams, null, logLevel);
        Main.run(args);
    }

    public static void dropAll(SimpleDatabaseConf dbParams, String logLevel)
    throws LiquibaseException, CommandLineParsingException, IOException
    {
        if(logLevel != null && "severe".equals(logLevel) == false)
        {
            logLevel = "severe";
        }
        String[] args = createCommandLineArgments("dropAll", dbParams, null, logLevel);
        Main.run(args);
    }

    public static void update(SimpleDatabaseConf dbParams, String changeLogFile, String logLevel)
    throws LiquibaseException, CommandLineParsingException, IOException
    {
        String[] args = createCommandLineArgments("update", dbParams, changeLogFile, logLevel);
        Main.run(args);
    }

    private static String[] createCommandLineArgments(String command, SimpleDatabaseConf params,
            String changeLogFile, String logLevel)
    {
        List<String> args = new LinkedList<>();
        if(changeLogFile != null)
        {
            args.add("--changeLogFile=" + IoCertUtil.expandFilepath(changeLogFile));
        }
        args.add("--username=" + params.getUsername());
        args.add("--password=" + params.getPassword());
        args.add("--url=" + params.getUrl());
        args.add("--driver=" + params.getDriver());
        String schema = params.getSchema();
        if(schema != null && schema.isEmpty() == false)
        {
            args.add("--defaultSchemaName=" + schema);
        }
        if(logLevel != null && logLevel.isEmpty() == false)
        {
            args.add("--logLevel=" + logLevel);
        }
        args.add(command);
        return args.toArray(new String[0]);
    }

}
