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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.dbtool.diffdb.DbDigestDiffWorker;
import org.xipki.ca.dbtool.port.DbPortWorker;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.DirPathCompleter;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "diff-digest-db",
        description = "diff digest XiPKI/EJBCA database")
@Service
public class DiffDigestDbCmd extends DbPortAction {

    @Option(name = "--ref-db",
            description = "database configuration file of the reference system\n"
                    + "(one of --ref-db and--ref-dir must be specified)")
    @Completion(FilePathCompleter.class)
    private String refDbConf;

    @Option(name = "--ref-dir",
            description = "directory of exported digest files of the reference system\n"
                    + "(one of --ref-db and--ref-dir must be specified)")
    @Completion(DirPathCompleter.class)
    private String refDir;

    @Option(name = "--target", required = true,
            description = "configuration file of the target database to be evaluated")
    @Completion(FilePathCompleter.class)
    private String dbconfFile;

    @Option(name = "--report-dir", required = true,
            description = "report directory\n(required)")
    @Completion(DirPathCompleter.class)
    private String reportDir;

    @Option(name = "--revoked-only")
    private Boolean revokedOnly = Boolean.FALSE;

    @Option(name = "-k",
            description = "number of certificates per SELECT")
    private Integer numCertsPerSelect = 1000;

    @Option(name = "--target-threads",
            description = "number of threads to query the target database")
    private Integer numTargetThreads = 40;

    @Option(name = "--ca-cert", multiValued = true,
            description = "Certificate of CAs to be considered\n(multi-valued)")
    @Completion(FilePathCompleter.class)
    private List<String> caCertFiles;

    protected DbPortWorker getDbPortWorker() throws Exception {
        Set<byte[]> caCerts = null;
        if (caCertFiles != null && !caCertFiles.isEmpty()) {
            caCerts = new HashSet<>(caCertFiles.size());
            for (String fileName : caCertFiles) {
                caCerts.add(IoUtil.read(fileName));
            }
        }

        return new DbDigestDiffWorker(datasourceFactory, passwordResolver, revokedOnly, refDir,
                refDbConf, dbconfFile, reportDir, numCertsPerSelect, numTargetThreads, caCerts);
    }

}
