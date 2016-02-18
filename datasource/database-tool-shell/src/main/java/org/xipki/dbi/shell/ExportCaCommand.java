/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.dbi.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.DirPathCompleter;
import org.xipki.console.karaf.FilePathCompleter;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.CaDbExporter;
import org.xipki.security.api.PasswordResolver;

/**
 * @author Lijun Liao
 */

@Command(scope = "dbtool", name = "export-ca", description="Export CA database")
@Service
public class ExportCaCommand extends XipkiOsgiCommandSupport
{
    private static final String DFLT_DBCONF_FILE = "ca-config/ca-db.properties";
    private static final int DFLT_NUM_CERTS_IN_BUNDLE = 1000;
    private static final int DFLT_NUM_CRLS = 30;

    @Option(name = "-dbconf",
            description = "Database configuration file")
    @Completion(FilePathCompleter.class)
    protected String dbconfFile = DFLT_DBCONF_FILE;

    @Option(name = "-outdir",
            description = "Required. Output directory",
            required = true)
    @Completion(DirPathCompleter.class)
    protected String outdir;

    @Option(name = "-n",
            description = "Number of certificates in one zip file")
    protected Integer numCertsInBundle = DFLT_NUM_CERTS_IN_BUNDLE;

    @Option(name = "-numcrls",
            description = "Number of CRLs in one zip file")
    protected Integer numCrls = DFLT_NUM_CRLS;

    @Option(name = "-resume")
    protected Boolean resume = Boolean.FALSE;

    @Reference
    private DataSourceFactory dataSourceFactory;

    @Reference
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CaDbExporter exporter = new CaDbExporter(dataSourceFactory, passwordResolver, dbconfFile, outdir, resume);
        exporter.exportDatabase(numCertsInBundle, numCrls);
        return null;
    }

}
