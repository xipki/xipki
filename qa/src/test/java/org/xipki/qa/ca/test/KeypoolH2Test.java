// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.Base64;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.pkix.cert.KeyCertBytesPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.qa.ca.FillKeypool;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.misc.NameId;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

/**
 * The keypool keypair generator of the CA ({@code KeypoolKeypairGenerator}): the pool is
 * filled by {@link FillKeypool}, the CA takes the keys of server-side generated key pairs
 * from the pool.
 *
 * @author Lijun Liao (xipki)
 */
public class KeypoolH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static final String PASSWORD = "keypool-password";

  private static final int NUM_KEYS = 2;

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  private static Path keypoolDbConf;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv("keypool");
    caManager = env.caManager();
    keypoolDbConf = env.extraDbConf("keypool");

    FillKeypool fill = new FillKeypool(new DataSourceFactory(), keypoolDbConf.toString());
    try {
      fill.execute(NUM_KEYS, "AES128/GCM", PASSWORD.toCharArray(), List.of(KeySpec.P256));
    } finally {
      fill.close();
    }

    caManager.addKeypairGen(new KeypairGenEntry("keypool1", "keypool",
        "datasource=keypool,password=" + PASSWORD + ",keyspecs=P256"));
    // only the keypool: the software generator is not used
    ChangeCaEntry change = new ChangeCaEntry(new NameId(null, CA));
    change.setKeypairGenNames(List.of("keypool1"));
    caManager.changeCa(change);
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void publicKeyDataContainsNoPrivateKey() throws Exception {
    try (DataSourceWrapper datasource = datasource();
         Connection conn = datasource.getConnection();
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery("SELECT PUKDATA FROM KEYPOOL")) {
      while (rs.next()) {
        // must be a SubjectPublicKeyInfo, not a PrivateKeyInfo
        SubjectPublicKeyInfo.fromEncoded(Base64.decode(rs.getString("PUKDATA")));
      }
    }
  }

  @Test
  public void keysAreTakenFromThePool() throws Exception {
    Assert.assertEquals(NUM_KEYS, keysInPool());

    X509Cert cert1 = generate("keypool1.example.org");
    Assert.assertEquals(NUM_KEYS - 1, keysInPool());
    X509Cert cert2 = generate("keypool2.example.org");
    Assert.assertEquals(NUM_KEYS - 2, keysInPool());
    Assert.assertNotEquals("different keys", cert1.publicKey(), cert2.publicKey());

    // the pool is empty
    Assert.assertThrows(CaMgmtException.class, () -> generate("keypool3.example.org"));
  }

  private static X509Cert generate(String commonName) throws Exception {
    KeyCertBytesPair keyCert = caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null);
    Assert.assertNotNull("private key", keyCert.key());
    return X509Util.parseCert(keyCert.cert());
  }

  private static int keysInPool() throws Exception {
    try (DataSourceWrapper datasource = datasource()) {
      return datasource.getCount(null, "KEYPOOL");
    }
  }

  private static DataSourceWrapper datasource() throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(keypoolDbConf)) {
      props.load(in);
    }
    return new DataSourceFactory().createDataSource("keypool-test", props);
  }

}
