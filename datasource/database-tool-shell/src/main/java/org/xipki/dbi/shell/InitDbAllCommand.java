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

@Command(scope = "dbtool", name = "initdb", description="Reset and initialize the CA and OCSP databases")
public class InitDbAllCommand extends LiquibaseCommand
{
    private static final String ca_schemaFile = "sql/ca-init.xml";
    private static final String ocsp_schemaFile = "sql/ocsp-init.xml";

    @Override
    protected Object doExecute()
    throws Exception
    {
        Map<String, SimpleDatabaseConf> dbConfs = getDatabaseConfs();

        SimpleDatabaseConf dbConf = dbConfs.get("ca");
        if(confirm("reset and initialize", dbConf, ca_schemaFile))
        {
            LiquibaseCommandLine.releaseLocks(dbConf, logLevel);
            LiquibaseCommandLine.dropAll(dbConf, logLevel);
            LiquibaseCommandLine.update(dbConf, ca_schemaFile, logLevel);
        }

        for(String dbName : dbConfs.keySet())
        {
            if(dbName.toLowerCase().contains("ocsp") == false)
            {
                continue;
            }

            dbConf = dbConfs.get(dbName);
            if(confirm("reset and initialize", dbConf, ocsp_schemaFile))
            {
                LiquibaseCommandLine.releaseLocks(dbConf, logLevel);
                LiquibaseCommandLine.dropAll(dbConf, logLevel);
                LiquibaseCommandLine.update(dbConf, ocsp_schemaFile, logLevel);
            }
        }
        return null;
    }

}
