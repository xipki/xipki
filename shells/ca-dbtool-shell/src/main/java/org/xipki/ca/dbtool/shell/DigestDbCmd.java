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
import org.xipki.ca.dbtool.diffdb.DbDigestExportWorker;
import org.xipki.ca.dbtool.port.DbPortWorker;
import org.xipki.console.karaf.completer.DirPathCompleter;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "digest-db",
        description = "digest XiPKI/EJBCA database")
@Service
public class DigestDbCmd extends DbPortAction {

    @Option(name = "--db-conf",
            required = true,
            description = "database configuration file")
    @Completion(FilePathCompleter.class)
    private String dbconfFile;

    @Option(name = "--out-dir",
            required = true,
            description = "output directory\n"
                    + "(required)")
    @Completion(DirPathCompleter.class)
    private String outdir;

    @Option(name = "-k",
            description = "number of certificates per SELECT")
    private Integer numCertsPerSelect = 1000;

    @Option(name = "--threads",
            description = "number of threads to query the database")
    private Integer numThreads = 10;

    @Override
    protected DbPortWorker getDbPortWorker() throws Exception {
        return new DbDigestExportWorker(datasourceFactory, passwordResolver, dbconfFile, outdir,
                numCertsPerSelect, numThreads);
    }

}
