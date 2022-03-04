/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.mgmt.db.DbWorker;
import org.xipki.ca.mgmt.db.diffdb.DigestDiffWorker;
import org.xipki.ca.mgmt.db.port.DbPortWorker;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completers;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Actions to operate on databases directly.
 *
 * @author Lijun Liao
 *
 */
public class DbActions {

  public abstract static class DbAction extends XiAction {

    protected DataSourceFactory datasourceFactory;

    @Reference
    protected PasswordResolver passwordResolver;

    public DbAction() {
      datasourceFactory = new DataSourceFactory();
    }

    protected abstract DbWorker getDbWorker()
        throws Exception;

    protected Object execute0()
        throws Exception {
      ExecutorService executor = Executors.newFixedThreadPool(1);
      DbWorker myRun = getDbWorker();
      executor.execute(myRun);

      executor.shutdown();
      while (true) {
        try {
          boolean terminated = executor.awaitTermination(1, TimeUnit.SECONDS);
          if (terminated) {
            break;
          }
        } catch (InterruptedException ex) {
          myRun.setStopMe(true);
        }
      }

      Exception ex = myRun.exception();
      if (ex != null) {
        throw ex;
      } else {
        return null;
      }
    } // method execute0

  } // class DbAction

  public abstract static class DbPortAction extends DbAction {

    @Option(name = "--quorum", aliases = "-q", description = "quorum of the password parts, " +
            "valid value is 0..10 (inclusive). 0 indicates no password will be applied.")
    private Integer quorum = 0;

    protected char[] readPassword() throws IOException {
      Args.range(quorum, "mk", 0, 10);
      if (quorum == 0) {
        return null;
      } else if (quorum == 1) {
        return readPassword("Master password");
      } else {
        char[][] parts = new char[quorum][];
        for (int i = 0; i < quorum; i++) {
          parts[i] = readPassword("Master password (part " + (i + 1) + "/" + quorum + ")");
        }
        return StringUtil.merge(parts);
      }
    }
  } // class DbAction

  @Command(scope = "ca", name = "diff-digest", description = "diff digest XiPKI database")
  @Service
  public static class DiffDigest extends DbAction {

    @Option(name = "--ref-db", required = true,
        description = "database configuration file of the reference system")
    @Completion(FileCompleter.class)
    private String refDbConf;

    @Option(name = "--target", required = true,
        description = "configuration file of the target database to be evaluated")
    @Completion(FileCompleter.class)
    private String dbconfFile;

    @Option(name = "--report-dir", required = true, description = "report directory")
    @Completion(Completers.DirCompleter.class)
    private String reportDir;

    @Option(name = "--revoked-only", description = "considers only the revoked certificates")
    private Boolean revokedOnly = Boolean.FALSE;

    @Option(name = "-k", description = "number of certificates per SELECT")
    private Integer numCertsPerSelect = 1000;

    @Option(name = "--target-threads",
        description = "number of threads to query the target database")
    private Integer numTargetThreads = 40;

    @Option(name = "--ca-cert", multiValued = true,
        description = "Certificate of CAs to be considered")
    @Completion(FileCompleter.class)
    private List<String> caCertFiles;

    @Override
    protected DbWorker getDbWorker()
        throws Exception {
      Set<byte[]> caCerts = null;
      if (caCertFiles != null && !caCertFiles.isEmpty()) {
        caCerts = new HashSet<>(caCertFiles.size());
        for (String fileName : caCertFiles) {
          byte[] derEncodedCert = X509Util.parseCert(new File(fileName)).getEncoded();
          caCerts.add(derEncodedCert);
        }
      }

      return new DigestDiffWorker(datasourceFactory, passwordResolver, revokedOnly,
          refDbConf, dbconfFile, reportDir, numCertsPerSelect, numTargetThreads, caCerts);
    } // method getDbPortWorker

  } // class DiffDigest

  @Command(scope = "ca", name = "export-ca", description = "export CA database")
  @Service
  public static class ExportCa extends DbPortAction {

    @Option(name = "--db-conf", required = true, description = "database configuration file")
    @Completion(FileCompleter.class)
    private String dbconfFile;

    @Option(name = "--out-dir", required = true, description = "output directory")
    @Completion(Completers.DirCompleter.class)
    private String outdir;

    @Option(name = "-n", description = "number of certificates in one zip file")
    private Integer numCertsInBundle = 10000;

    @Option(name = "-k", description = "number of certificates per SELECT")
    private Integer numCertsPerCommit = 100;

    @Option(name = "--resume", description = "resume from the last successful point")
    private Boolean resume = Boolean.FALSE;

    @Override
    protected DbPortWorker getDbWorker()
        throws Exception {
      return new DbPortWorker.ExportCaDb(datasourceFactory, passwordResolver, dbconfFile, outdir,
          resume, numCertsInBundle, numCertsPerCommit, readPassword());
    }

  } // class ExportCa

  @Command(scope = "ca", name = "export-ocsp", description = "export OCSP database")
  @Service
  public static class ExportOcsp extends DbPortAction {

    @Option(name = "--db-conf", required = true, description = "database configuration file.")
    @Completion(FileCompleter.class)
    private String dbconfFile;

    @Option(name = "--out-dir", required = true, description = "output directory")
    @Completion(Completers.DirCompleter.class)
    private String outdir;

    @Option(name = "-n", description = "number of certificates in one zip file")
    private Integer numCertsInBundle = 10000;

    @Option(name = "-k", description = "number of certificates per SELECT")
    private Integer numCertsPerSelect = 100;

    @Option(name = "--resume", description = "resume from the last successful point")
    private Boolean resume = Boolean.FALSE;

    @Override
    protected DbPortWorker getDbWorker()
        throws Exception {
      return new DbPortWorker.ExportOcspDb(datasourceFactory, passwordResolver, dbconfFile, outdir,
          resume, numCertsInBundle, numCertsPerSelect, readPassword());
    }

  } // class ExportOcsp

  @Command(scope = "ca", name = "import-ca", description = "import CA database")
  @Service
  public static class ImportCa extends DbPortAction {

    @Option(name = "--db-conf", required = true, description = "database configuration file")
    @Completion(FileCompleter.class)
    private String dbconfFile;

    @Option(name = "--in-dir", required = true, description = "input directory")
    @Completion(Completers.DirCompleter.class)
    private String indir;

    @Option(name = "-k", description = "number of certificates per commit")
    private Integer numCertsPerCommit = 100;

    @Option(name = "--resume", description = "resume from the last successful point")
    private Boolean resume = Boolean.FALSE;

    @Override
    protected DbPortWorker getDbWorker()
        throws Exception {
      return new DbPortWorker.ImportCaDb(datasourceFactory, passwordResolver, dbconfFile, resume,
          indir, numCertsPerCommit, readPassword());
    }

  } // class ImportCa

  @Command(scope = "ca", name = "import-ocsp", description = "import OCSP database")
  @Service
  public static class ImportOcsp extends DbPortAction {

    @Option(name = "--db-conf", required = true, description = "database configuration file")
    @Completion(FileCompleter.class)
    private String dbconfFile;

    @Option(name = "--in-dir", required = true, description = "input directory")
    @Completion(Completers.DirCompleter.class)
    private String indir;

    @Option(name = "-k", description = "number of certificates per commit")
    private Integer numCertsPerCommit = 100;

    @Option(name = "--resume", description = "resume from the last successful point")
    private Boolean resume = Boolean.FALSE;

    @Override
    protected DbPortWorker getDbWorker()
        throws Exception {
      return new DbPortWorker.ImportOcspDb(datasourceFactory, passwordResolver, dbconfFile, resume,
          indir, numCertsPerCommit, readPassword());
    }

  } // class ImportOcsp

  @Command(scope = "ca", name = "import-ocspfromca",
      description = "import OCSP database from CA data")
  @Service
  public static class ImportOcspfromca extends DbPortAction {

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

    @Override
    protected DbPortWorker getDbWorker()
        throws Exception {
      return new DbPortWorker.ImportOcspFromCaDb(datasourceFactory, passwordResolver, dbconfFile,
          publisherName, resume, indir, numCertsPerCommit, readPassword());
    }

  } // class ImportOcspfromca

}
