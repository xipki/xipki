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
import org.xipki.dbi.OcspFromCaDbImporter;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "dbtool", name = "import-ocspfromca", description="Import OCSP database from CA data")
public class ImportOcspFromCaCommand extends XipkiOsgiCommandSupport
{
    private static final String DFLT_DBCONF_FILE = "ca-config/ocsp-db.properties";
    private static final String DFLT_PUBLISHER = "OCSP.PUBLISHER";

    @Option(name = "-dbconf",
            description = "Database configuration file")
    protected String dbconfFile = DFLT_DBCONF_FILE;

    @Option(name = "-indir",
            description = "Required. Input directory",
            required = true)
    protected String indir;

    @Option(name = "-publisher",
            description = "Publisher name")
    protected String publisherName = DFLT_PUBLISHER;

    @Option(name = "-resume")
    protected Boolean resume = Boolean.FALSE;

    private DataSourceFactory dataSourceFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        OcspFromCaDbImporter importer = new OcspFromCaDbImporter(
                dataSourceFactory, passwordResolver, dbconfFile, publisherName, resume);
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
