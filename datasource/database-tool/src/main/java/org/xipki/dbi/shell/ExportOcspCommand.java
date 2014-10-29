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
import org.xipki.dbi.OcspDbExporter;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "dbtool", name = "export-ocsp", description="Export OCSP database")
public class ExportOcspCommand extends XipkiOsgiCommandSupport
{
    private static final String DFLT_DBCONF_FILE = "ca-config/ocsp-db.properties";
    private static final int DFLT_NUM_CERTS_IN_BUNDLE = 1000;

    @Option(name = "-dbconf",
            description = "Database configuration file.")
    protected String dbconfFile = DFLT_DBCONF_FILE;

    @Option(name = "-outdir",
            description = "Required. Output directory",
            required = true)
    protected String outdir;

    @Option(name = "-n",
            description = "Number of certificates in one zip file")
    protected Integer numCertsInBundle = DFLT_NUM_CERTS_IN_BUNDLE;

    @Option(name = "-resume")
    protected Boolean resume = Boolean.FALSE;

    private DataSourceFactory dataSourceFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        OcspDbExporter exporter = new OcspDbExporter(dataSourceFactory, passwordResolver, dbconfFile, outdir, resume);
        exporter.exportDatabase(numCertsInBundle);
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
