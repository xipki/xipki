/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
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
        OcspDbExporter exporter = new OcspDbExporter(dataSourceFactory, passwordResolver, dbconfFile, outdir);
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
