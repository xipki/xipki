// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
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
import org.xipki.util.misc.NameId;

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
 * The tools for the OCSP database: export and import ({@code ExportOcspDb},
 * {@code ImportOcspDb}), import from an export of the CA database ({@code ImportOcspFromCaDb}),
 * and the digest diff of the CA database against the OCSP database. The reference is the OCSP
 * database filled by the OCSP publisher of the CA.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspDbToolsH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static final String PUBLISHER = "ocsp-publisher";

  private static final char[] PASSWORD = "CHANGEIT".toCharArray();

  private static final int NUM_CERTS = 5;

  private static CaH2TestEnv env;

  private static DataSourceFactory datasourceFactory;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(true);
    datasourceFactory = new DataSourceFactory();
    CaManagerImpl caManager = env.caManager();
    caManager.addPublisher(new PublisherEntry(new NameId(null, PUBLISHER), "ocsp",
        "datasource=ocsp,publish.goodcerts=true"));
    caManager.addPublisherToCa(PUBLISHER, CA);

    List<BigInteger> serials = new ArrayList<>();
    for (int i = 0; i < NUM_CERTS; i++) {
      serials.add(X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
          "CN=ocspdb" + i + ".example.org,O=myorg,C=DE", null, null).cert()).serialNumber());
    }
    caManager.revokeCertificate(CA, serials.get(0), CrlReason.KEY_COMPROMISE, null);
    caManager.revokeCertificate(CA, serials.get(1), CrlReason.CERTIFICATE_HOLD, null);

    // the publisher has filled the OCSP database
    try (DataSourceWrapper ocsp = datasource(env.ocspDbConf())) {
      Assert.assertEquals(NUM_CERTS, ocsp.getCount(null, "CERT"));
    }
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void exportAndImportOcspDatabase() throws Exception {
    Path exportDir = env.workDir().resolve("ocsp-export");
    // 2 certificates per bundle, 1 per SELECT: several bundles and batches
    run(new DbPortWorker.ExportOcspDb(datasourceFactory, env.ocspDbConf().toString(),
        exportDir.toString(), false, 2, 1, PASSWORD));

    Path target = env.newDatabase("ocsp-import", "ocsp-init.h2.sql");
    run(new DbPortWorker.ImportOcspDb(datasourceFactory, target.toString(), false,
        exportDir.toString(), 2, PASSWORD));

    assertSameOcspContent(env.ocspDbConf(), target);
  }

  @Test
  public void importOcspDatabaseFromCaExport() throws Exception {
    Path exportDir = env.workDir().resolve("ca-export-for-ocsp");
    run(new DbPortWorker.ExportCaDb(datasourceFactory, env.caconfDbConf().toString(),
        env.caDbConf().toString(), exportDir.toString(), false, 2, 1, PASSWORD));

    Path target = env.newDatabase("ocsp-from-ca", "ocsp-init.h2.sql");
    run(new DbPortWorker.ImportOcspFromCaDb(datasourceFactory, target.toString(), PUBLISHER,
        false, exportDir.toString(), 2, PASSWORD));

    // the same content as published by the CA
    assertSameOcspContent(env.ocspDbConf(), target);
  }

  @Test
  public void digestDiffOfCaAgainstOcspDatabase() throws Exception {
    assertNoDiff(env.caDbConf(), env.ocspDbConf(), "diff-ca-ocsp");
  }

  @Test
  public void digestDiffOfOcspAgainstCaDatabase() throws Exception {
    assertNoDiff(env.ocspDbConf(), env.caDbConf(), "diff-ocsp-ca");
  }

  @Test
  public void digestDiffReportsDifferences() throws Exception {
    Path exportDir = env.workDir().resolve("ocsp-export-diff");
    run(new DbPortWorker.ExportOcspDb(datasourceFactory, env.ocspDbConf().toString(),
        exportDir.toString(), false, 2, 1, PASSWORD));
    Path target = env.newDatabase("ocsp-import-diff", "ocsp-init.h2.sql");
    run(new DbPortWorker.ImportOcspDb(datasourceFactory, target.toString(), false,
        exportDir.toString(), 2, PASSWORD));

    // one good certificate is revoked in the target only
    try (DataSourceWrapper datasource = datasource(target);
         Connection conn = datasource.getConnection();
         Statement stmt = conn.createStatement()) {
      Assert.assertEquals(1, stmt.executeUpdate("UPDATE CERT SET REV=1, RR=1, RT=1 "
          + "WHERE ID=(SELECT MIN(ID) FROM CERT WHERE REV=0)"));
    }

    Path reportDir = env.workDir().resolve("diff-ocsp-changed");
    run(new DigestDiffWorker(datasourceFactory, false, env.ocspDbConf().toString(),
        target.toString(), reportDir.toString(), 2, 1, null));
    Assert.assertEquals("lines in diff", 1, lines(reportDir, "diff"));
    Assert.assertEquals("lines in error", 0, lines(reportDir, "error"));
  }

  // ---------------------------------------------------------------- helpers

  private static void assertNoDiff(Path ref, Path target, String reportName) throws Exception {
    Path reportDir = env.workDir().resolve(reportName);
    run(new DigestDiffWorker(datasourceFactory, false, ref.toString(), target.toString(),
        reportDir.toString(), 2, 1, null));
    Assert.assertEquals("certificates compared", NUM_CERTS, sum(reportDir));
    for (String file : List.of("diff", "missing", "unexpected", "error")) {
      Assert.assertEquals("lines in " + file, 0, lines(reportDir, file));
    }
  }

  /** The number of compared certificates ("sum" in overview.txt). */
  private static int sum(Path reportDir) throws IOException {
    try (Stream<Path> files = Files.walk(reportDir)) {
      int sum = 0;
      for (Path f : (Iterable<Path>) files.filter(
          p -> p.getFileName().toString().equals("overview.txt"))::iterator) {
        for (String line : Files.readAllLines(f)) {
          if (line.trim().startsWith("sum")) {
            sum += Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
          }
        }
      }
      return sum;
    }
  }

  private static void assertSameOcspContent(Path expected, Path actual) throws Exception {
    try (DataSourceWrapper source = datasource(expected);
         DataSourceWrapper target = datasource(actual)) {
      Assert.assertEquals("issuers", rows(source,
              "SELECT SUBJECT, S1C, REV_INFO, CERT FROM ISSUER ORDER BY SUBJECT"),
          rows(target, "SELECT SUBJECT, S1C, REV_INFO, CERT FROM ISSUER ORDER BY SUBJECT"));
      String certs = "SELECT SN, NBEFORE, NAFTER, REV, RR, RT, RIT, HASH FROM CERT ORDER BY SN";
      List<String> expectedCerts = rows(source, certs);
      Assert.assertEquals(NUM_CERTS, expectedCerts.size());
      Assert.assertEquals("certificates", expectedCerts, rows(target, certs));
    }
  }

  /** All rows of the query, each as its columns joined with |. */
  private static List<String> rows(DataSourceWrapper datasource, String sql) throws Exception {
    List<String> rows = new ArrayList<>();
    try (Connection conn = datasource.getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery(sql)) {
      int n = rs.getMetaData().getColumnCount();
      while (rs.next()) {
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i <= n; i++) {
          sb.append(i == 1 ? "" : "|").append(rs.getString(i));
        }
        rows.add(sb.toString());
      }
    }
    return rows;
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

  /** Number of non-blank lines in the report files with the given name. */
  private static int lines(Path reportDir, String fileName) throws IOException {
    if (!Files.exists(reportDir)) {
      return 0;
    }
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
