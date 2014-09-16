/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi.shell;

import java.util.Map;

import org.apache.felix.gogo.commands.Command;
import org.xipki.liquibase.LiquibaseDatabaseConf;

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
        Map<String, LiquibaseDatabaseConf> dbConfs = getDatabaseConfs();

        LiquibaseDatabaseConf dbConf = dbConfs.get("ca");
        resetAndInit(dbConf, ca_schemaFile);

        for(String dbName : dbConfs.keySet())
        {
            if(dbName.toLowerCase().contains("ocsp") == false)
            {
                continue;
            }

            dbConf = dbConfs.get(dbName);
            resetAndInit(dbConf, ocsp_schemaFile);
        }
        return null;
    }

}
