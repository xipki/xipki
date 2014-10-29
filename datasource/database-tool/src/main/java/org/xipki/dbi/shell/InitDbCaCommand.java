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

@Command(scope = "dbtool", name = "initdb-ca", description="Reset and initialize the CA database")
public class InitDbCaCommand extends LiquibaseCommand
{
    private static final String schemaFile = "sql/ca-init.xml";

    @Override
    protected Object doExecute()
    throws Exception
    {
        Map<String, LiquibaseDatabaseConf> dbConfs = getDatabaseConfs();

        LiquibaseDatabaseConf dbConf = dbConfs.get("ca");
        resetAndInit(dbConf, schemaFile);
        return null;
    }

}
