/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.OcspDbImporter;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "dbtool", name = "import-ocsp", description="Import OCSP database")
public class ImportOcspCommand extends XipkiOsgiCommandSupport
{
    private static final String DFLT_DBCONF_FILE = "ca-config/ocsp-db.properties";

    @Option(name = "-dbconf",
            description = "Database configuration file.\nDefault is " + DFLT_DBCONF_FILE)
    protected String dbconfFile;

    @Option(name = "-indir",
            description = "Required. Input directory",
            required = true)
    protected String indir;

    private DataSourceFactory dataSourceFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(dbconfFile == null)
        {
            dbconfFile = DFLT_DBCONF_FILE;
        }
        OcspDbImporter importer = new OcspDbImporter(dataSourceFactory, passwordResolver, dbconfFile);
        importer.importDatabase(indir);
        return null;
    }

    public void setDataSourceFactory(DataSourceFactory dataSourceFactory)
    {
        this.dataSourceFactory = dataSourceFactory;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }
}
