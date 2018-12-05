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

package org.xipki.ca.mgmt.shell.db;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.mgmt.db.port.DbPortWorker;
import org.xipki.shell.Completers;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "import-ocspfromca",
    description = "import OCSP database from CA data")
@Service
public class ImportOcspFromCaAction extends DbPortAction {

  private static final String DFLT_PUBLISHER = "ocsp-publisher";

  @Option(name = "--db-conf", required = true, description = "database configuration file")
  @Completion(FileCompleter.class)
  private String dbconfFile;

  @Option(name = "--in-dir", required = true, description = "input directory")
  @Completion(Completers.DirCompleter.class)
  private String indir;

  @Option(name = "--publisher", description = "publisher name")
  private String publisherName = DFLT_PUBLISHER;

  @Option(name = "-k", description = "number of certificates per commit")
  private Integer numCertsPerCommit = 100;

  @Option(name = "--resume", description = "resume from the last successful point")
  private Boolean resume = Boolean.FALSE;

  @Option(name = "--test", description = "just test the import, no real import")
  private Boolean testOnly = Boolean.FALSE;

  @Override
  protected DbPortWorker getDbPortWorker() throws Exception {
    return new DbPortWorker.ImportOcspFromCaDb(datasourceFactory, passwordResolver, dbconfFile,
        publisherName, resume, indir, numCertsPerCommit.intValue(), testOnly.booleanValue());
  }

}
