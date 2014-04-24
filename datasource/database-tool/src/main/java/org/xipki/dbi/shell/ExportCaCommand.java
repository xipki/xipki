/*
 * Copyright 2014 xipki.org
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
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.CaDbExporter;
import org.xipki.security.api.PasswordResolver;

@Command(scope = "dbtool", name = "export-ca", description="Export CA database")
public class ExportCaCommand extends OsgiCommandSupport
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
            description = "Number of certificates in one zip file. Default is 500")
    protected Integer           numCertsInBundle;

    @Option(name = "-numcrls",
            description = "Number of certificates in one zip file. Default is 30")
    protected Integer           numCrls;

    private DataSourceFactory dataSourceFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numCertsInBundle == null)
        {
            numCertsInBundle = 500;
        }
        if(numCrls == null)
        {
            numCrls = 30;
        }
        CaDbExporter exporter = new CaDbExporter(dataSourceFactory, passwordResolver, dbconfFile);
        exporter.exportDatabase(outdir, numCertsInBundle, numCrls);
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
