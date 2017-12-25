/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.dbtool.port.DbPortWorker;
import org.xipki.ca.dbtool.port.ca.CaDbExportWorker;
import org.xipki.console.karaf.completer.DirPathCompleter;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "export-ca",
        description = "export CA database")
@Service
public class ExportCaCmd extends DbPortAction {

    private static final String DFLT_DBCONF_FILE = "xipki/ca-config/ca-db.properties";

    @Option(name = "--db-conf",
            description = "database configuration file")
    @Completion(FilePathCompleter.class)
    private String dbconfFile = DFLT_DBCONF_FILE;

    @Option(name = "--out-dir",
            required = true,
            description = "output directory\n"
                    + "(required)")
    @Completion(DirPathCompleter.class)
    private String outdir;

    @Option(name = "-n",
            description = "number of certificates in one zip file")
    private Integer numCertsInBundle = 10000;

    @Option(name = "-k",
            description = "number of certificates per SELECT")
    private Integer numCertsPerCommit = 100;

    @Option(name = "--resume")
    private Boolean resume = Boolean.FALSE;

    @Option(name = "--test",
            description = "just test the export, no real export")
    private Boolean onlyTest = Boolean.FALSE;

    @Override
    protected DbPortWorker getDbPortWorker() throws Exception {
        return new CaDbExportWorker(datasourceFactory, passwordResolver, dbconfFile, outdir, resume,
                numCertsInBundle, numCertsPerCommit, onlyTest);
    }

}
