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
import org.xipki.dbi.CaDbExporter;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "dbtool", name = "export-ca", description="Export CA database")
public class ExportCaCommand extends XipkiOsgiCommandSupport
{
    private static final String DFLT_DBCONF_FILE = "ca-config/ca-db.properties";
    private static final int DFLT_NUM_CERTS_IN_BUNDLE = 1000;
    private static final int DFLT_NUM_CRLS = 30;

    @Option(name = "-dbconf",
            description = "Database configuration file.\nDefault is " + DFLT_DBCONF_FILE)
    protected String dbconfFile;

    @Option(name = "-outdir",
            description = "Required. Output directory",
            required = true)
    protected String outdir;

    @Option(name = "-n",
            description = "Number of certificates in one zip file. Default is " + DFLT_NUM_CERTS_IN_BUNDLE)
    protected Integer numCertsInBundle;

    @Option(name = "-numcrls",
            description = "Number of CRLs in one zip file. Default is " + DFLT_NUM_CRLS)
    protected Integer numCrls;

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
        if(numCertsInBundle == null)
        {
            numCertsInBundle = DFLT_NUM_CERTS_IN_BUNDLE;
        }
        if(numCrls == null)
        {
            numCrls = DFLT_NUM_CRLS;
        }
        CaDbExporter exporter = new CaDbExporter(dataSourceFactory, passwordResolver, dbconfFile, outdir);
        exporter.exportDatabase(numCertsInBundle, numCrls);
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
