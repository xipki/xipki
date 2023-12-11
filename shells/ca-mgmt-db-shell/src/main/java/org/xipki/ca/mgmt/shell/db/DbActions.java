// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell.db;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.mgmt.db.DbWorker;
import org.xipki.ca.mgmt.db.diffdb.DigestDiffWorker;
import org.xipki.ca.mgmt.db.port.DbPortWorker;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.DatabaseType;
import org.xipki.datasource.ScriptRunner;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.ConfigurableProperties;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

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
 *
 */
public class DbActions {

  private static String printDbInfo(ConfigurableProperties dbProps, int scriptFilePathLen) {
    Args.notNull(dbProps, "dbProps");

    String schema = dbProps.getProperty("liquibase.schema");
    if (schema != null) {
      schema = schema.trim();
      if (schema.isEmpty()) {
        schema = null;
      }
    }

    String user = dbProps.getProperty("dataSource.user");
    if (user == null) {
      user = dbProps.getProperty("username");
    }

    String url = dbProps.getProperty("jdbcUrl");
    if (url != null) {
      return printDbInfo(user, url, schema, scriptFilePathLen);
    }

    String datasourceClassName = dbProps.getProperty("dataSourceClassName");
    if (datasourceClassName == null) {
      throw new IllegalArgumentException("unsupported configuration");
    }

    StringBuilder urlBuilder = new StringBuilder();

    datasourceClassName = datasourceClassName.toLowerCase();

    if (datasourceClassName.contains("org.h2.")) {
      String dataSourceUrl = dbProps.getProperty("dataSource.url");
      urlBuilder.append(dataSourceUrl);
      if (schema != null) {
        urlBuilder.append(";INIT=CREATE SCHEMA IF NOT EXISTS ").append(schema);
      }
    } else if (datasourceClassName.contains("mysql.")) {
      urlBuilder.append("jdbc:mysql://")
          .append(dbProps.getProperty("dataSource.serverName")).append(":")
          .append(dbProps.getProperty("dataSource.port")).append("/")
          .append(dbProps.getProperty("dataSource.databaseName"));
    } else if (datasourceClassName.contains("mariadb.")) {
      String str = dbProps.getProperty("dataSource.url");
      if (StringUtil.isNotBlank(str)) {
        urlBuilder.append(str);
      } else {
        urlBuilder.append("jdbc:mariadb://")
            .append(dbProps.getProperty("dataSource.serverName")).append(":")
            .append(dbProps.getProperty("dataSource.port")).append("/")
            .append(dbProps.getProperty("dataSource.databaseName"));
      }
    } else if (datasourceClassName.contains("oracle.")) {
      String str = dbProps.getProperty("dataSource.URL");
      if (StringUtil.isNotBlank(str)) {
        urlBuilder.append(str);
      } else {
        urlBuilder.append("jdbc:oracle:thin:@")
            .append(dbProps.getProperty("dataSource.serverName")).append(":")
            .append(dbProps.getProperty("dataSource.portNumber")).append(":")
            .append(dbProps.getProperty("dataSource.databaseName"));
      }
    } else if (datasourceClassName.contains("com.ibm.db2.")) {
      schema = dbProps.getProperty("dataSource.currentSchema");

      urlBuilder.append("jdbc:db2://")
          .append(dbProps.getProperty("dataSource.serverName")).append(":")
          .append(dbProps.getProperty("dataSource.portNumber")).append("/")
          .append(dbProps.getProperty("dataSource.databaseName"));
    } else if (datasourceClassName.contains("postgresql.")
        || datasourceClassName.contains("impossibl.postgres.")) {
      String serverName;
      String portNumber;
      String databaseName;
      if (datasourceClassName.contains("postgresql.")) {
        serverName = dbProps.getProperty("dataSource.serverName");
        portNumber = dbProps.getProperty("dataSource.portNumber");
        databaseName = dbProps.getProperty("dataSource.databaseName");
      } else {
        serverName = dbProps.getProperty("dataSource.host");
        portNumber = dbProps.getProperty("dataSource.port");
        databaseName = dbProps.getProperty("dataSource.database");
      }

      urlBuilder.append("jdbc:postgresql://")
          .append(serverName).append(":").append(portNumber).append("/").append(databaseName);
    } else if (datasourceClassName.contains("hsqldb.")) {
      String dataSourceUrl = dbProps.getProperty("dataSource.url");
      urlBuilder.append(dataSourceUrl);
    } else {
      throw new IllegalArgumentException("unsupported database type " + datasourceClassName);
    }

    url = urlBuilder.toString();

    return printDbInfo(user, url, schema, scriptFilePathLen);
  } // method getInstance

  private static String printDbInfo(String username, String url, String schema, int scriptFilePathLen) {
    String boundary = "-".repeat(2 + Math.max(
        "Start executing script ".length() + scriptFilePathLen,
        "script file: ".length() + url.length()));
    String msg = boundary + "\n       user: " + username + "\n        URL: " + url;
    if (schema != null) {
      msg += "\n     schema: " + schema;
    }
    System.out.println(msg);
    return boundary;
  }

  public abstract static class DbAction extends XiAction {

    protected DataSourceFactory datasourceFactory;

    public DbAction() {
      datasourceFactory = new DataSourceFactory();
    }

    protected abstract DbWorker getDbWorker() throws Exception;

    protected Object execute0() throws Exception {
      ExecutorService executor = Executors.newFixedThreadPool(1);
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

  @Command(scope = "ca", name = "export-ca", description = "export CA database")
  @Service
  public static class ExportCa extends DbPortAction {

    @Option(name = "--caconf-db-conf", description = "CA configuration database file")
    @Completion(FileCompleter.class)
    private String caConfDbConfFile;

    @Option(name = "--db-conf", required = true, description = "CA database file")
    @Completion(FileCompleter.class)
    private String dbConfFile;

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
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ExportCaDb(datasourceFactory, caConfDbConfFile, dbConfFile,
          outdir, resume, numCertsInBundle, numCertsPerCommit, readPassword());
    }

  } // class ExportCa

  @Command(scope = "ca", name = "export-ca-certstore",
      description = "export CA cerstore database (without the CA configuration)")
  @Service
  public static class ExportCaCertStore extends DbPortAction {

    @Option(name = "--db-conf", required = true, description = "CA certstore database file")
    @Completion(FileCompleter.class)
    private String dbConfFile;

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
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ExportCaCertStoreDb(datasourceFactory, dbConfFile,
          outdir, resume, numCertsInBundle, numCertsPerCommit, readPassword());
    }

  } // class ExportCa

  public abstract static class DbPortAction extends DbAction {

    @Option(name = "--password", description = "password, as plaintext or PBE-encrypted, or 'NO' for no password")
    private String passwordHint;

    @Override
    protected char[] readPassword() throws IOException, PasswordResolverException {
      if ("NO".equalsIgnoreCase(passwordHint)) {
        return null;
      }
      return readPasswordIfNotSet("Please enter password of the ZIP file", passwordHint);
    }
  } // class DbAction

  @Command(scope = "ca", name = "diff-digest", description = "diff digest XiPKI database")
  @Service
  public static class DiffDigest extends DbAction {

    @Option(name = "--ref-db", required = true, description = "database configuration file of the reference system")
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

    @Option(name = "--target-threads", description = "number of threads to query the target database")
    private Integer numTargetThreads = 40;

    @Option(name = "--ca-cert", multiValued = true, description = "Certificate of CAs to be considered")
    @Completion(FileCompleter.class)
    private List<String> caCertFiles;

    @Override
    protected DbWorker getDbWorker() throws Exception {
      Set<byte[]> caCerts = null;
      if (caCertFiles != null && !caCertFiles.isEmpty()) {
        caCerts = new HashSet<>(caCertFiles.size());
        for (String fileName : caCertFiles) {
          caCerts.add(X509Util.parseCert(new File(fileName)).getEncoded());
        }
      }

      return new DigestDiffWorker(datasourceFactory, revokedOnly,
          refDbConf, dbconfFile, reportDir, numCertsPerSelect, numTargetThreads, caCerts);
    } // method getDbPortWorker

  } // class DiffDigest

  @Command(scope = "ca", name = "sql", description = "Run SQL script")
  @Service
  public static class Sql extends XiAction {

    @Option(name = "--db-conf", required = true, description = "database configuration file")
    @Completion(FileCompleter.class)
    private String dbConfFile;

    @Argument(name = "script", required = true, description = "SQL script file")
    @Completion(FileCompleter.class)
    private String scriptFile;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      ConfigurableProperties props = new ConfigurableProperties();
      try (InputStream is = Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile)))) {
        props.load(is);
      }

      // only one connection is needed.
      props.setProperty("minimumIdle", "1");
      try (DataSourceWrapper dataSource = new DataSourceFactory().createDataSource("default", props)) {
        DatabaseType dbType = dataSource.getDatabaseType();
        String type;
        switch (dbType) {
          case H2:
            type = "h2";
            break;
          case POSTGRES:
            type = "postgresql";
            break;
          case DB2:
            type = "db2";
            break;
          case ORACLE:
            type = "oracle";
            break;
          case MYSQL:
          case MARIADB:
            type = "mysql";
            break;
          case HSQL:
            type = "hsqldb";
            break;
          default:
            throw new IllegalArgumentException("unknown database type " + dbType);
        }

        scriptFile = expandFilepath(scriptFile);
        Path p = Paths.get(scriptFile);

        if (!Files.exists(p)) {
          String fileName = p.getFileName().toString();
          int idx = fileName.lastIndexOf('.');
          fileName = fileName.substring(0, idx) + "." + type + fileName.substring(idx);
          Path parentP = p.getParent();
          p = parentP == null ? Paths.get(fileName) : Paths.get(parentP.toString(), fileName);
          if (!Files.exists(p)) {
            p = parentP == null ? Paths.get(type, fileName) : Paths.get(parentP.toString(), type, fileName);
            if (!Files.exists(p)) {
              throw new IllegalCmdParamException("Could not find script file " + scriptFile);
            }
          }
        }

        String boundary = printDbInfo(props, p.toString().length());
        println("script file: " + p);
        if (!force) {
          if (!confirm("Do you want to execute the SQL script?", 3)) {
            throw new CmdFailure("User cancelled");
          }
        }

        println("Start executing script " + p);
        ScriptRunner.runScript(dataSource, p.toString());
        println("  End executing script " + p);
        System.out.println(boundary);
        return null;
      }
    }
  } // class Sql

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
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ExportOcspDb(datasourceFactory, dbconfFile, outdir,
          resume, numCertsInBundle, numCertsPerSelect, readPassword());
    }

  } // class ExportOcsp

  @Command(scope = "ca", name = "import-ca", description = "import CA database")
  @Service
  public static class ImportCa extends DbPortAction {

    @Option(name = "--caconf-db-conf", required = true, description = "CA configuration database file")
    @Completion(FileCompleter.class)
    private String caconfDbFile;

    @Option(name = "--db-conf", required = true, description = "CA database file")
    @Completion(FileCompleter.class)
    private String dbConfFile;

    @Option(name = "--in-dir", required = true, description = "input directory")
    @Completion(Completers.DirCompleter.class)
    private String indir;

    @Option(name = "-k", description = "number of certificates per commit")
    private Integer numCertsPerCommit = 100;

    @Option(name = "--resume", description = "resume from the last successful point")
    private Boolean resume = Boolean.FALSE;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportCaDb(datasourceFactory, caconfDbFile, dbConfFile,
          resume, indir, numCertsPerCommit, readPassword());
    }

  } // class ImportCa

  @Command(scope = "ca", name = "import-ca-certstore",
      description = "import CA certstore database only (without the CA configuration)")
  @Service
  public static class ImportCaCertStore extends DbPortAction {

    @Option(name = "--db-conf", required = true, description = "CA certstore database file")
    @Completion(FileCompleter.class)
    private String dbConfFile;

    @Option(name = "--in-dir", required = true, description = "input directory")
    @Completion(Completers.DirCompleter.class)
    private String indir;

    @Option(name = "-k", description = "number of certificates per commit")
    private Integer numCertsPerCommit = 100;

    @Option(name = "--resume", description = "resume from the last successful point")
    private Boolean resume = Boolean.FALSE;

    @Override
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportCaCertStoreDb(datasourceFactory, dbConfFile,
          resume, indir, numCertsPerCommit, readPassword());
    }

  } // class ImportCaCertStore

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
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportOcspDb(datasourceFactory,
          dbconfFile, resume, indir, numCertsPerCommit, readPassword());
    }

  } // class ImportOcsp

  @Command(scope = "ca", name = "import-ocspfromca",
      description = "import OCSP database from CA data")
  @Service
  public static class ImportOcspfromCa extends DbPortAction {

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
    protected DbPortWorker getDbWorker() throws Exception {
      return new DbPortWorker.ImportOcspFromCaDb(datasourceFactory, dbconfFile,
          publisherName, resume, indir, numCertsPerCommit, readPassword());
    }

  } // class ImportOcspfromca

}
