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

@Command(scope = "dbtool", name = "reset-ocspdb", description="Reset and initialize the OCSP databases")
public class InitDbOcspCommand extends LiquibaseCommand
{
    private static final String schemaFile = "sql/ocsp-init.xml";

    @Override
    protected Object doExecute()
    throws Exception
    {
        Map<String, SimpleDatabaseConf> dbConfs = getDatabaseConfs();

        for(String dbName : dbConfs.keySet())
        {
            if(dbName.toLowerCase().contains("ocsp") == false)
            {
                continue;
            }

            SimpleDatabaseConf dbConf = dbConfs.get(dbName);
            if(confirm("reset and initialize", dbConf, schemaFile))
            {
                LiquibaseCommandLine.releaseLocks(dbConf, logLevel);
                LiquibaseCommandLine.dropAll(dbConf, logLevel);
                LiquibaseCommandLine.update(dbConf, schemaFile, logLevel);
            }
        }
        return null;
    }

}
