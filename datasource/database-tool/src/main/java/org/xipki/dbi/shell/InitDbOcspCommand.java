/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi.shell;

import java.util.Map;

import org.apache.felix.gogo.commands.Command;
import org.xipki.dbi.liquibase.LiquibaseDatabaseConf;

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
        Map<String, LiquibaseDatabaseConf> dbConfs = getDatabaseConfs();

        for(String dbName : dbConfs.keySet())
        {
            if(dbName.toLowerCase().contains("ocsp") == false)
            {
                continue;
            }

            LiquibaseDatabaseConf dbConf = dbConfs.get(dbName);
            resetAndInit(dbConf, schemaFile);
        }
        return null;
    }

}
