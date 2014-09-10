/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi.shell;

import java.util.Map;

import org.apache.felix.gogo.commands.Command;
import org.xipki.database.api.SimpleDatabaseConf;
import org.xipki.dbi.LiquibaseCommandLine;

/**
 * @author Lijun Liao
 */

@Command(scope = "dbtool", name = "initdb-ca", description="Reset and initialize the CA database")
public class InitDbCaCommand extends LiquibaseCommand
{
    private static final String schemaFile = "sql/ca-init.xml";

    @Override
    protected Object doExecute()
    throws Exception
    {
        Map<String, SimpleDatabaseConf> dbConfs = getDatabaseConfs();

        SimpleDatabaseConf dbConf = dbConfs.get("ca");
        if(confirm("reset and initialize", dbConf, schemaFile))
        {
            LiquibaseCommandLine.releaseLocks(dbConf, logLevel);
            LiquibaseCommandLine.dropAll(dbConf, logLevel);
            LiquibaseCommandLine.update(dbConf, schemaFile, logLevel);
        }
        return null;
    }

}
