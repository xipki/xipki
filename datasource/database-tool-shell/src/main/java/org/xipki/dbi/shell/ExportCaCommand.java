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
    @Option(name = "-dbconf",
            description = "Required. Database configuration file",
            required = true)
    protected String            dbconfFile;

    @Option(name = "-outdir",
            description = "Required. Output directory",
            required = true)
    protected String            outdir;

    @Option(name = "-n",
            description = "Number of certificates in one zip file. Default is 1000")
    protected Integer           numCertsInBundle;

    @Option(name = "-numcrls",
            description = "Number of CRLs in one zip file. Default is 30")
    protected Integer           numCrls;

    private DataSourceFactory dataSourceFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numCertsInBundle == null)
        {
            numCertsInBundle = 1000;
        }
        if(numCrls == null)
        {
            numCrls = 30;
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
