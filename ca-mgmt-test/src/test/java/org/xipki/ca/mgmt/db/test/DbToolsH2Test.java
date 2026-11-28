// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.mgmt.db.DbWorker;
import org.xipki.ca.mgmt.db.diffdb.DigestDiffWorker;
import org.xipki.ca.mgmt.db.port.DbPortWorker;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.conf.ConfigurableProperties;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * The database tools of the CA: export of the CA configuration and the certificate store,
 * import into empty databases, and the comparison of the certificate stores, on in-memory H2
 * databases.
 *
 * @author Lijun Liao (xipki)
 */
public class DbToolsH2Test {

  private static final char[] PASSWORD = "CHANGEIT".toCharArray();

  private static final int NUM_CERTS = 5;

  private static CaH2TestEnv env;

  private static DataSourceFactory datasourceFactory;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    datasourceFactory = new DataSourceFactory();
    CaManagerImpl caManager = env.caManager();
    BigInteger first = null;
    for (int i = 0; i < NUM_CERTS; i++) {
      BigInteger serial = X509Util.parseCert(caManager.generateKeyCert(CaH2TestEnv.CA_NAME,
          CaH2TestEnv.PROFILE_TLS, "CN=db" + i + ".example.org,O=myorg,C=DE", null, null)
          .cert()).serialNumber();
      if (first == null) {
        first = serial;
      }
    }
    caManager.revokeCertificate(CaH2TestEnv.CA_NAME, first, CrlReason.KEY_COMPROMISE, null);
    caManager.generateCrlOnDemand(CaH2TestEnv.CA_NAME);
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void exportImportAndCompare() throws Exception {
    Path exportDir = env.workDir().resolve("export");
    // 2 certificates per bundle, 1 per SELECT: several bundles and batches
    run(new DbPortWorker.ExportCaDb(datasourceFactory, env.caconfDbConf().toString(),
        env.caDbConf().toString(), exportDir.toString(), false, 2, 1, PASSWORD));

    Path caconf = env.newDatabase("caconf-import", true);
    Path ca = env.newDatabase("ca-import", false);
    run(new DbPortWorker.ImportCaDb(datasourceFactory, caconf.toString(), ca.toString(), false,
        exportDir.toString(), 2, PASSWORD));

    // the CA configuration
    try (DataSourceWrapper source = datasource(env.caconfDbConf());
         DataSourceWrapper target = datasource(caconf)) {
      for (String table : List.of("CA", "PROFILE", "CA_HAS_PROFILE", "REQUESTOR",
          "CA_HAS_REQUESTOR", "KEYPAIR_GEN")) {
        Assert.assertEquals("rows of " + table, count(source, table), count(target, table));
      }
      Assert.assertEquals(CaH2TestEnv.CA_NAME, target.getFirstStringValue(null, "CA", "NAME",
          "NAME='" + CaH2TestEnv.CA_NAME + "'"));
    }

    // the certificate store
    try (DataSourceWrapper source = datasource(env.caDbConf());
         DataSourceWrapper target = datasource(ca)) {
      for (String table : List.of("CA", "CERT", "CRL")) {
        Assert.assertEquals("rows of " + table, count(source, table), count(target, table));
      }
      Assert.assertEquals(NUM_CERTS, count(target, "CERT"));
    }

    // the certificates, with their revocation status, row by row
    try (DataSourceWrapper source = datasource(env.caDbConf());
         DataSourceWrapper target = datasource(ca)) {
      Assert.assertEquals(certRows(source), certRows(target));
    }
  }

  @Test
  public void diffOfImportedStore() throws Exception {
    Path exportDir = env.workDir().resolve("export-diff");
    run(new DbPortWorker.ExportCaDb(datasourceFactory, env.caconfDbConf().toString(),
        env.caDbConf().toString(), exportDir.toString(), false, 10, 10, PASSWORD));
    Path caconf = env.newDatabase("caconf-diff", true);
    Path ca = env.newDatabase("ca-diff", false);
    run(new DbPortWorker.ImportCaDb(datasourceFactory, caconf.toString(), ca.toString(), false,
        exportDir.toString(), 10, PASSWORD));

    Path reportDir = env.workDir().resolve("diff-report");
    Files.createDirectories(reportDir);
    run(new DigestDiffWorker(datasourceFactory, false, env.caDbConf().toString(),
        ca.toString(), reportDir.toString(), 2, 2, null));

    Assert.assertEquals(NUM_CERTS, lines(reportDir, "good"));
    for (String file : List.of("diff", "missing", "unexpected", "error")) {
      Assert.assertEquals("lines in " + file, 0, lines(reportDir, file));
    }
  }

  @Test
  public void wrongPasswordIsRejected() throws Exception {
    Path exportDir = env.workDir().resolve("export-pwd");
    run(new DbPortWorker.ExportCaDb(datasourceFactory, env.caconfDbConf().toString(),
        env.caDbConf().toString(), exportDir.toString(), false, 10, 10, PASSWORD));

    Path caconf = env.newDatabase("caconf-pwd", true);
    Path ca = env.newDatabase("ca-pwd", false);
    DbPortWorker worker = new DbPortWorker.ImportCaDb(datasourceFactory, caconf.toString(),
        ca.toString(), false, exportDir.toString(), 10, "wrong".toCharArray());
    worker.run();
    Assert.assertNotNull("import with a wrong password", worker.exception());
  }

  @Test
  public void diffDetectsMissingCertificates() throws Exception {
    // compare with an empty certificate store
    Path ca = env.newDatabase("ca-empty", false);
    Path caconf = env.newDatabase("caconf-empty", true);
    Path exportDir = env.workDir().resolve("export-empty");
    // import only the configuration and the CAs, no certificates: export a store, then delete
    run(new DbPortWorker.ExportCaDb(datasourceFactory, env.caconfDbConf().toString(),
        env.caDbConf().toString(), exportDir.toString(), false, 10, 10, PASSWORD));
    run(new DbPortWorker.ImportCaDb(datasourceFactory, caconf.toString(), ca.toString(), false,
        exportDir.toString(), 10, PASSWORD));
    try (DataSourceWrapper target = datasource(ca);
         Connection conn = target.getConnection()) {
      conn.createStatement().executeUpdate("DELETE FROM CERT WHERE ID IN "
          + "(SELECT ID FROM CERT ORDER BY ID LIMIT 2)");
    }

    Path reportDir = env.workDir().resolve("diff-report-missing");
    Files.createDirectories(reportDir);
    run(new DigestDiffWorker(datasourceFactory, false, env.caDbConf().toString(),
        ca.toString(), reportDir.toString(), 2, 2, null));
    Assert.assertEquals(2, lines(reportDir, "missing"));
    Assert.assertEquals(NUM_CERTS - 2, lines(reportDir, "good"));
  }

  private static void run(DbWorker worker) throws Exception {
    worker.run();
    if (worker.exception() != null) {
      throw worker.exception();
    }
  }

  private static DataSourceWrapper datasource(Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return datasourceFactory.createDataSource("test", props);
  }

  /** Serial number, revocation status and certificate of all rows in CERT, ordered. */
  private static List<String> certRows(DataSourceWrapper datasource) throws Exception {
    List<String> rows = new ArrayList<>();
    try (Connection conn = datasource.getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery("SELECT SN, REV, RR, RT, CERT FROM CERT ORDER BY SN")) {
      while (rs.next()) {
        rows.add(rs.getString("SN") + "|" + rs.getInt("REV") + "|" + rs.getInt("RR") + "|"
            + rs.getLong("RT") + "|" + rs.getString("CERT"));
      }
    }
    return rows;
  }

  private static int count(DataSourceWrapper datasource, String table) throws Exception {
    return datasource.getCount(null, table);
  }

  /** Number of lines in the report file with the given name (found in any sub folder). */
  private static int lines(Path reportDir, String fileName) throws IOException {
    try (Stream<Path> files = Files.walk(reportDir)) {
      int sum = 0;
      for (Path f : (Iterable<Path>) files.filter(
          p -> p.getFileName().toString().equals(fileName))::iterator) {
        try (Stream<String> lines = Files.lines(f)) {
          sum += (int) lines.filter(l -> !l.isBlank()).count();
        }
      }
      return sum;
    }
  }

}
