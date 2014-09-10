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
            description = "Database configuration file")
    protected String dbconfFile = DFLT_DBCONF_FILE;

    @Option(name = "-outdir",
            description = "Required. Output directory",
            required = true)
    protected String outdir;

    @Option(name = "-n",
            description = "Number of certificates in one zip file")
    protected Integer numCertsInBundle = DFLT_NUM_CERTS_IN_BUNDLE;

    @Option(name = "-numcrls",
            description = "Number of CRLs in one zip file")
    protected Integer numCrls = DFLT_NUM_CRLS;

    @Option(name = "-resume")
    protected Boolean resume = Boolean.FALSE;

    private DataSourceFactory dataSourceFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CaDbExporter exporter = new CaDbExporter(dataSourceFactory, passwordResolver, dbconfFile, outdir, resume);
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
