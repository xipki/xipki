// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.server.CaUtil;
import org.xipki.ca.server.db.DbCaConfStore;
import org.xipki.ca.server.db.DbCertStore;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.misc.UniqueIdGenerator;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Map;

/**
 * The CA accepts only databases with its own certificate format (DBSCHEMA entry CERTFORMAT).
 *
 * @author Lijun Liao (xipki)
 */
public class CertFormatCheckH2Test {

  /** The certificate format of this CA. */
  private static final String OWN_FORMAT = "X509";

  private static final String OTHER_FORMAT = "C509";

  private static CaH2TestEnv env;

  private static final DataSourceFactory datasourceFactory = new DataSourceFactory();

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void checkCertFormat() {
    Assert.assertEquals(OWN_FORMAT, CaUtil.CERT_FORMAT);
    Assert.assertNull(CaUtil.checkCertFormat(Map.of("CERTFORMAT", OWN_FORMAT), "db"));
    // absent: X509
    String absent = CaUtil.checkCertFormat(Map.of(), "db");
    Assert.assertEquals("X509".equals(OWN_FORMAT), absent == null);

    String other = CaUtil.checkCertFormat(Map.of("CERTFORMAT", OTHER_FORMAT), "db");
    Assert.assertNotNull(other);
    Assert.assertTrue(other, other.contains("has the certificate format " + OTHER_FORMAT));

    for (String invalid : new String[]{"c509", "x509", "", "X.509"}) {
      String msg = CaUtil.checkCertFormat(Map.of("CERTFORMAT", invalid), "db");
      Assert.assertNotNull(invalid, msg);
      Assert.assertTrue(msg, msg.contains("invalid CERTFORMAT '" + invalid + "'"));
    }
  }

  @Test
  public void caConfDatabaseWithOtherCertFormatIsRejected() throws Exception {
    Path conf = env.newDatabase("caconf-other-format", true);
    setCertFormat(conf, OTHER_FORMAT);
    try (DataSourceWrapper ds = datasource(conf)) {
      CaMgmtException ex = Assert.assertThrows(CaMgmtException.class,
          () -> new DbCaConfStore(ds, env.workDir().toString()));
      Assert.assertTrue(ex.getMessage(),
          ex.getMessage().contains("has the certificate format " + OTHER_FORMAT));
    }
  }

  @Test
  public void caDatabaseWithOtherCertFormatIsRejected() throws Exception {
    Path caconfConf = env.newDatabase("caconf-own-format", true);
    Path caConf = env.newDatabase("ca-other-format", false);
    setCertFormat(caConf, OTHER_FORMAT);
    try (DataSourceWrapper caconfDs = datasource(caconfConf);
         DataSourceWrapper caDs = datasource(caConf)) {
      DbCaConfStore caconfStore = new DbCaConfStore(caconfDs, env.workDir().toString());
      CaMgmtException ex = Assert.assertThrows(CaMgmtException.class,
          () -> new DbCertStore(caDs, caconfStore, new UniqueIdGenerator(0, 0)));
      Assert.assertTrue(ex.getMessage(),
          ex.getMessage().contains("CA database") && ex.getMessage().contains(OTHER_FORMAT));
    }
  }

  @Test
  public void databasesWithOwnCertFormatAreAccepted() throws Exception {
    Path caconfConf = env.newDatabase("caconf-explicit-format", true);
    Path caConf = env.newDatabase("ca-explicit-format", false);
    setCertFormat(caconfConf, OWN_FORMAT);
    setCertFormat(caConf, OWN_FORMAT);
    try (DataSourceWrapper caconfDs = datasource(caconfConf);
         DataSourceWrapper caDs = datasource(caConf)) {
      DbCaConfStore caconfStore = new DbCaConfStore(caconfDs, env.workDir().toString());
      new DbCertStore(caDs, caconfStore, new UniqueIdGenerator(0, 0));
    }
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

  private static DataSourceWrapper datasource(Path conf) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(conf)) {
      props.load(in);
    }
    return datasourceFactory.createDataSource("test-" + conf.getFileName(), props);
  }

}
