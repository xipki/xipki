// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.mgmt.db.DbWorker;
import org.xipki.ca.mgmt.db.diffdb.DigestDiffWorker;
import org.xipki.ca.mgmt.db.port.DbPortWorker;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.DirPathCompleter;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.datasource.DataSourceFactory;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.datasource.ScriptRunner;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.password.PasswordResolverException;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Actions to operate on databases directly.
 *
 * @author Lijun Liao (xipki)
 */
public class DbCommands {

  abstract static class DbCommand extends ShellBaseCommand {

    protected final DataSourceFactory datasourceFactory = new DataSourceFactory();

    protected abstract DbWorker getDbWorker() throws Exception;

    protected char[] readZipPassword(String passwordHint)
        throws IOException, PasswordResolverException {
      return readPasswordIfNotSet(
          "Please enter password to decrypt / encrypt the ZIP file", passwordHint);
    }

    @Override
    public void run() {
      ExecutorService executor = Executors.newFixedThreadPool(1);
      try {
        DbWorker myRun = getDbWorker();
        executor.execute(myRun);
        executor.shutdown();
        while (true) {
          try {
            if (executor.awaitTermination(1, TimeUnit.SECONDS)) {
              break;
            }
          } catch (InterruptedException ex) {
            myRun.setStopMe(true);
            Thread.currentThread().interrupt();
            break;
          }
        }

        Exception ex = myRun.exception();
        if (ex != null) {
          throw new RuntimeException(ex.getMessage(), ex);
        }
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  abstract static class DbPortCommand extends DbCommand {

    @Option(names = "--password", description = "password, as plaintext or PBE-encrypted")
    private String passwordHint;

    protected char[] readPassword() throws IOException, PasswordResolverException {
      return readZipPassword(passwordHint);
    }
  }

  @Command(name = "export-ca", description = "export CA database", mixinStandardHelpOptions = true)
  static class ExportCaCommand extends DbPortCommand {

    @Option(names = "--caconf-db-conf", description = "CA configuration database file")
    @Completion(FilePathCompleter.class)
    private String caConfDbConfFile;

    @Option(names = "--db-conf", required = true, description = "CA database file")
    @Completion(FilePathCompleter.class)
    private String dbConfFile;

    @Option(names = "--out-dir", required = true, description = "output directory")
    @Completion(DirPathCompleter.class)
    private String outdir;

    @Option(names = "-n", description = "number of certificates in one zip file")
    @Completion(FilePathCompleter.class)
    private Integer numCertsInBundle = 10000;

    @Option(names = "-k", description = "number of certificates per SELECT")
    private Integer numCertsPerCommit = 100;

    @Option(names = "--resume", description = "resume from the last successful point")
    private boolean resume;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ExportCaDb(datasourceFactory, caConfDbConfFile,
          dbConfFile, outdir, resume, numCertsInBundle, numCertsPerCommit, readPassword());
    }
  }

  @Command(name = "export-ca-certstore",
      description = "export CA certstore database without the CA configuration",
      mixinStandardHelpOptions = true)
  static class ExportCaCertstoreCommand extends DbPortCommand {

    @Option(names = "--db-conf", required = true, description = "CA certstore database file")
    @Completion(FilePathCompleter.class)
    private String dbConfFile;

    @Option(names = "--out-dir", required = true, description = "output directory")
    @Completion(DirPathCompleter.class)
    private String outdir;

    @Option(names = "-n", description = "number of certificates in one zip file")
    @Completion(FilePathCompleter.class)
    private Integer numCertsInBundle = 10000;

    @Option(names = "-k", description = "number of certificates per SELECT")
    private Integer numCertsPerCommit = 100;

    @Option(names = "--resume", description = "resume from the last successful point")
    private boolean resume;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ExportCaCertStoreDb(datasourceFactory, dbConfFile,
          outdir, resume, numCertsInBundle, numCertsPerCommit, readPassword());
    }
  }

  @Command(name = "sql", description = "run SQL script", mixinStandardHelpOptions = true)
  static class SqlCommand extends ShellBaseCommand {

    @Option(names = "--db-conf", required = true, description = "database configuration file")
    @Completion(FilePathCompleter.class)
    private String dbConfFile;

    @Parameters(index = "0", description = "SQL script file")
    @Completion(FilePathCompleter.class)
    private String scriptFile;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        ConfigurableProperties props = new ConfigurableProperties();
        try (InputStream is = Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile)))) {
          props.load(is);
        }

        props.setProperty("minimumIdle", "1");
        try (DataSourceWrapper dataSource = new DataSourceFactory()
            .createDataSource("default", props)) {
          String type = CaMgmtUtil.dbTypeName(dataSource.databaseType());
          scriptFile = IoUtil.expandFilepath(scriptFile);
          Path p = CaMgmtUtil.resolveSqlScript(scriptFile, type);

          String boundary = CaMgmtUtil.printDbInfo(props, p.toString().length());
          println("script file: " + p);
          if (!force && !confirmYesNo("Do you want to execute the SQL script?")) {
            throw new RuntimeException("User cancelled");
          }

          println("Start executing script " + p);
          File logDir = new File("logs");
          logDir.mkdirs();
          Path createDbLogPath = new File(logDir, "create_db.log").toPath();
          Path createDbErrorLogPath = new File(logDir, "create_db_error.log").toPath();
          ScriptRunner.runScript(dataSource, p.toString(), createDbLogPath, createDbErrorLogPath);
          println("  End executing script " + p);
          System.out.println(boundary);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not run SQL script: " + ex.getMessage(), ex);
      }
    }

    private boolean confirmYesNo(String prompt) throws Exception {
      return confirmAction(prompt);
    }
  }

  @Command(name = "export-ocsp", description = "export OCSP database",
      mixinStandardHelpOptions = true)
  static class ExportOcspCommand extends DbPortCommand {

    @Option(names = "--db-conf", required = true, description = "database configuration file")
    @Completion(FilePathCompleter.class)
    private String dbconfFile;

    @Option(names = "--out-dir", required = true, description = "output directory")
    @Completion(DirPathCompleter.class)
    private String outdir;

    @Option(names = "-n", description = "number of certificates in one zip file")
    private Integer numCertsInBundle = 10000;

    @Option(names = "-k", description = "number of certificates per SELECT")
    private Integer numCertsPerSelect = 100;

    @Option(names = "--resume", description = "resume from the last successful point")
    private boolean resume;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ExportOcspDb(datasourceFactory, dbconfFile,
          outdir, resume, numCertsInBundle, numCertsPerSelect, readPassword());
    }
  }

  @Command(name = "import-ca", description = "import CA database", mixinStandardHelpOptions = true)
  static class ImportCaCommand extends DbPortCommand {

    @Option(names = "--caconf-db-conf", required = true, description = "CA configuration DB file")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caconfDbFile;

    @Option(names = "--db-conf", required = true, description = "CA database file")
    @Completion(FilePathCompleter.class)
    private String dbConfFile;

    @Option(names = "--in-dir", required = true, description = "input directory")
    @Completion(DirPathCompleter.class)
    private String indir;

    @Option(names = "-k", description = "number of certificates per commit")
    @Completion(FilePathCompleter.class)
    private Integer numCertsPerCommit = 100;

    @Option(names = "--resume", description = "resume from the last successful point")
    private boolean resume;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportCaDb(datasourceFactory, caconfDbFile,
          dbConfFile, resume, indir, numCertsPerCommit, readPassword());
    }
  }

  @Command(name = "import-ca-certstore",
      description = "import CA certstore database only without the CA configuration",
      mixinStandardHelpOptions = true)
  static class ImportCaCertstoreCommand extends DbPortCommand {

    @Option(names = "--db-conf", required = true, description = "CA certstore database file")
    @Completion(FilePathCompleter.class)
    private String dbConfFile;

    @Option(names = "--in-dir", required = true, description = "input directory")
    @Completion(DirPathCompleter.class)
    private String indir;

    @Option(names = "-k", description = "number of certificates per commit")
    private Integer numCertsPerCommit = 100;

    @Option(names = "--resume", description = "resume from the last successful point")
    private boolean resume;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportCaCertStoreDb(datasourceFactory,
          dbConfFile, resume, indir, numCertsPerCommit, readPassword());
    }
  }

  @Command(name = "import-ocsp", description = "import OCSP database",
      mixinStandardHelpOptions = true)
  static class ImportOcspCommand extends DbPortCommand {

    @Option(names = "--db-conf", required = true, description = "database configuration file")
    @Completion(FilePathCompleter.class)
    private String dbconfFile;

    @Option(names = "--in-dir", required = true, description = "input directory")
    @Completion(DirPathCompleter.class)
    private String indir;

    @Option(names = "-k", description = "number of certificates per commit")
    private Integer numCertsPerCommit = 100;

    @Option(names = "--resume", description = "resume from the last successful point")
    private boolean resume;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportOcspDb(datasourceFactory,
          dbconfFile, resume, indir, numCertsPerCommit, readPassword());
    }
  }

  @Command(name = "import-ocspfromca", description = "import OCSP database from CA data",
      mixinStandardHelpOptions = true)
  static class ImportOcspFromCaCommand extends DbPortCommand {

    @Option(names = "--db-conf", required = true, description = "database configuration file")
    @Completion(FilePathCompleter.class)
    private String dbconfFile;

    @Option(names = "--in-dir", required = true, description = "input directory")
    @Completion(DirPathCompleter.class)
    private String indir;

    @Option(names = "--publisher", description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String publisherName = "ocsp-publisher";

    @Option(names = "-k", description = "number of certificates per commit")
    private Integer numCertsPerCommit = 100;

    @Option(names = "--resume", description = "resume from the last successful point")
    private boolean resume;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportOcspFromCaDb(datasourceFactory, dbconfFile,
          publisherName, resume, indir, numCertsPerCommit, readPassword());
    }
  }

  @Command(name = "diff-digest", description = "diff digest XiPKI database",
      mixinStandardHelpOptions = true)
  static class DiffDigestCommand extends DbCommand {

    @Option(names = "--ref-db", required = true, description = "reference database config file")
    @Completion(FilePathCompleter.class)
    private String refDbConf;

    @Option(names = "--target", required = true, description = "target database config file")
    @Completion(FilePathCompleter.class)
    private String dbconfFile;

    @Option(names = "--report-dir", required = true, description = "report directory")
    @Completion(DirPathCompleter.class)
    private String reportDir;

    @Option(names = "--revoked-only", description = "considers only revoked certificates")
    private boolean revokedOnly;

    @Option(names = "-k", description = "number of certificates per SELECT")
    private Integer numCertsPerSelect = 1000;

    @Option(names = "--target-threads", description = "number of target DB threads")
    private Integer numTargetThreads = 40;

    @Option(names = "--ca-cert", description = "CA certificate files to be considered")
    @Completion(FilePathCompleter.class)
    private List<String> caCertFiles;

    @Override
    protected DbWorker getDbWorker() throws Exception {
      Set<byte[]> caCerts = null;
      if (CollectionUtil.isNotEmpty(caCertFiles)) {
        caCerts = new HashSet<>(caCertFiles.size());
        for (String fileName : caCertFiles) {
          caCerts.add(X509Util.parseCert(new File(fileName)).getEncoded());
        }
      }
      return new DigestDiffWorker(datasourceFactory, revokedOnly, refDbConf,
          dbconfFile, reportDir, numCertsPerSelect, numTargetThreads, caCerts);
    }
  }
}
