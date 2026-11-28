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
import org.xipki.util.conf.ConfigurableProperties;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

/**
 * The certificate format of the database tools, given by the DBSCHEMA entry CERTFORMAT: absent
 * or X509 for X.509, C509 for C509, any other value is rejected. Databases and export files
 * with different formats are rejected before anything is written.
 *
 * @author Lijun Liao (xipki)
 */
public class CertFormatH2Test {

  /** The certificate format of the databases created by this project. */
  private static final String OWN_FORMAT = "X509";

  private static final String OTHER_FORMAT = "C509";

  private static final char[] PASSWORD = "CHANGEIT".toCharArray();

  private static CaH2TestEnv env;

  private static DataSourceFactory datasourceFactory;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    datasourceFactory = new DataSourceFactory();
    CaManagerImpl caManager = env.caManager();
    caManager.generateKeyCert(CaH2TestEnv.CA_NAME, CaH2TestEnv.PROFILE_TLS,
        "CN=format.example.org,O=myorg,C=DE", null, null);
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void exportWritesCertFormat() throws Exception {
    Path exportDir = export("export-format");
    ExportCrypt.decrypt(exportDir);
    String certstore = Files.readString(exportDir.resolve("ca-certstore.json"),
        StandardCharsets.UTF_8);
    Assert.assertTrue(certstore, certstore.replace(" ", "")
        .contains("\"certFormat\":\"" + OWN_FORMAT + "\""));
  }

  @Test
  public void exportAndImportWithExplicitCertFormat() throws Exception {
    // CERTFORMAT given explicitly in all databases: the same as absent for X509
    Path exportDir = export("export-explicit");
    Path caconf = env.newDatabase("caconf-explicit", true);
    Path ca = env.newDatabase("ca-explicit", false);
    setCertFormat(caconf, OWN_FORMAT);
    setCertFormat(ca, OWN_FORMAT);
    run(new DbPortWorker.ImportCaDb(datasourceFactory, caconf.toString(), ca.toString(), false,
        exportDir.toString(), 10, PASSWORD));
    Assert.assertEquals(1, count(ca, "CA"));
  }

  @Test
  public void invalidCertFormatStopsExport() throws Exception {
    for (String invalid : new String[]{"c509", "x509", "", "CBOR"}) {
      Path caconf = env.newDatabase("caconf-invalid", true);
      Path ca = env.newDatabase("ca-invalid", false);
      setCertFormat(ca, invalid);
      assertFails("invalid CERTFORMAT '" + invalid + "'",
          new DbPortWorker.ExportCaDb(datasourceFactory, caconf.toString(), ca.toString(),
              env.workDir().resolve("export-invalid-" + invalid).toString(),
              false, 10, 10, PASSWORD));
    }
  }

  @Test
  public void databasesWithDifferentCertFormatsStopExport() throws Exception {
    Path caconf = env.newDatabase("caconf-mixed", true);
    Path ca = env.newDatabase("ca-mixed", false);
    setCertFormat(ca, OTHER_FORMAT);
    assertFails("certificate format mismatch",
        new DbPortWorker.ExportCaDb(datasourceFactory, caconf.toString(), ca.toString(),
            env.workDir().resolve("export-mixed").toString(), false, 10, 10, PASSWORD));
  }

  @Test
  public void importIntoOtherCertFormatStopsBeforeWriting() throws Exception {
    Path exportDir = export("export-to-other");
    Path caconf = env.newDatabase("caconf-other", true);
    Path ca = env.newDatabase("ca-other", false);
    setCertFormat(caconf, OTHER_FORMAT);
    setCertFormat(ca, OTHER_FORMAT);

    assertFails("certificate format mismatch",
        new DbPortWorker.ImportCaDb(datasourceFactory, caconf.toString(), ca.toString(), false,
            exportDir.toString(), 10, PASSWORD));

    // nothing was written
    Assert.assertEquals(0, count(caconf, "CA"));
    Assert.assertEquals(0, count(ca, "CA"));
    Assert.assertEquals(0, count(ca, "CERT"));
    Assert.assertEquals(OTHER_FORMAT, certFormat(caconf));
  }

  @Test
  public void certstoreWithOtherCertFormatStopsBeforeWriting() throws Exception {
    Path exportDir = export("export-certstore-other");
    ExportCrypt.decrypt(exportDir);
    Path certstoreFile = exportDir.resolve("ca-certstore.json");
    String json = Files.readString(certstoreFile, StandardCharsets.UTF_8);
    String changed = json.replaceFirst("(\"certFormat\"\\s*:\\s*\")" + OWN_FORMAT + "\"",
        "$1" + OTHER_FORMAT + "\"");
    Assert.assertNotEquals("certFormat not found in " + json, json, changed);
    Files.writeString(certstoreFile, changed, StandardCharsets.UTF_8);
    ExportCrypt.encrypt(exportDir);

    Path caconf = env.newDatabase("caconf-certstore-other", true);
    Path ca = env.newDatabase("ca-certstore-other", false);
    assertFails("certificate format mismatch",
        new DbPortWorker.ImportCaDb(datasourceFactory, caconf.toString(), ca.toString(), false,
            exportDir.toString(), 10, PASSWORD));

    // also the CA configuration was not imported
    Assert.assertEquals(0, count(caconf, "CA"));
    Assert.assertEquals(0, count(ca, "CERT"));
  }

  @Test
  public void diffOfDifferentCertFormatsStops() throws Exception {
    Path ca = env.newDatabase("ca-diff-other", false);
    setCertFormat(ca, OTHER_FORMAT);
    Path reportDir = env.workDir().resolve("diff-report-other");
    Files.createDirectories(reportDir);
    assertFails("certificate format mismatch",
        new DigestDiffWorker(datasourceFactory, false, env.caDbConf().toString(),
            ca.toString(), reportDir.toString(), 2, 2, null));
  }

  @Test
  public void ocspExportWithInvalidCertFormatStops() throws Exception {
    Path ocsp = env.newDatabase("ocsp-invalid", "ocsp-init.h2.sql");
    setCertFormat(ocsp, "X.509");
    assertFails("invalid CERTFORMAT 'X.509'",
        new DbPortWorker.ExportOcspDb(datasourceFactory, ocsp.toString(),
            env.workDir().resolve("export-ocsp-invalid").toString(), false, 10, 10, PASSWORD));
  }

  @Test
  public void oldSchemaVersionStopsExport() throws Exception {
    Path caconf = env.newDatabase("caconf-v6", true);
    Path ca = env.newDatabase("ca-v6", false);
    try (DataSourceWrapper ds = datasource(caconf);
         Connection conn = ds.getConnection();
         Statement stmt = conn.createStatement()) {
      stmt.executeUpdate("UPDATE DBSCHEMA SET VALUE2='6' WHERE NAME='VERSION'");
    }
    assertFails("schema version < 7 is not supported",
        new DbPortWorker.ExportCaDb(datasourceFactory, caconf.toString(), ca.toString(),
            env.workDir().resolve("export-v6").toString(), false, 10, 10, PASSWORD));
  }

  private static Path export(String name) throws Exception {
    Path exportDir = env.workDir().resolve(name);
    run(new DbPortWorker.ExportCaDb(datasourceFactory, env.caconfDbConf().toString(),
        env.caDbConf().toString(), exportDir.toString(), false, 10, 10, PASSWORD));
    return exportDir;
  }

  /** Decrypts (unpacks) an export folder, or encrypts it again, with {@link #PASSWORD}. */
  private static class ExportCrypt extends DbPortWorker {

    ExportCrypt() throws Exception {
      super(datasourceFactory, env.caDbConf().toString(), PASSWORD);
    }

    static void decrypt(Path exportDir) throws Exception {
      ExportCrypt c = new ExportCrypt();
      try {
        c.decrypt(exportDir.toString());
      } finally {
        c.datasource.close();
      }
    }

    static void encrypt(Path exportDir) throws Exception {
      ExportCrypt c = new ExportCrypt();
      try {
        c.encrypt(exportDir.toFile());
      } finally {
        c.datasource.close();
      }
    }

    @Override
    protected void run0() {
    }

    @Override
    protected void close0() {
    }

  }

  private static void run(DbWorker worker) throws Exception {
    worker.run();
    if (worker.exception() != null) {
      throw worker.exception();
    }
  }

  /** Runs the worker and asserts that it fails with the text in the message of the cause. */
  private static void assertFails(String expectedText, DbWorker worker) {
    worker.run();
    Throwable ex = worker.exception();
    Assert.assertNotNull("expected failure with '" + expectedText + "'", ex);
    StringBuilder messages = new StringBuilder();
    for (Throwable t = ex; t != null; t = t.getCause()) {
      messages.append(t.getMessage()).append('\n');
    }
    Assert.assertTrue("expected '" + expectedText + "' in\n" + messages,
        messages.toString().contains(expectedText));
  }

  /** Sets the DBSCHEMA entry CERTFORMAT, removes it if value is null. */
  private static void setCertFormat(Path dbConf, String value) throws Exception {
    try (DataSourceWrapper ds = datasource(dbConf);
         Connection conn = ds.getConnection()) {
      try (Statement stmt = conn.createStatement()) {
        stmt.executeUpdate("DELETE FROM DBSCHEMA WHERE NAME='CERTFORMAT'");
      }
      if (value != null) {
        try (PreparedStatement ps = conn.prepareStatement(
            "INSERT INTO DBSCHEMA (NAME, VALUE2) VALUES ('CERTFORMAT', ?)")) {
          ps.setString(1, value);
          ps.executeUpdate();
        }
      }
    }
  }

  private static String certFormat(Path dbConf) throws Exception {
    try (DataSourceWrapper ds = datasource(dbConf)) {
      return ds.getDbSchema(null).get("CERTFORMAT");
    }
  }

  private static int count(Path dbConf, String table) throws Exception {
    try (DataSourceWrapper ds = datasource(dbConf)) {
      return ds.getCount(null, table);
    }
  }

  private static DataSourceWrapper datasource(Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return datasourceFactory.createDataSource("test-" + conf.getFileName(), props);
  }

}
