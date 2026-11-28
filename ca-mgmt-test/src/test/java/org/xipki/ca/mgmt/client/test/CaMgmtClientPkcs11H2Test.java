// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.client.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.ca.server.servlet.CaMgmtTestServer;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs11.P11Module;
import org.xipki.pkix.pkcs11.P11Slot;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.X509KeypairWithCert;
import org.xipki.pkix.util.KeyUtil;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * PKCS#11 token information via the management client ({@code getTokenInfoP11}), on the
 * in-memory HSM xihsm.
 *
 * @author Lijun Liao (xipki)
 */
public class CaMgmtClientPkcs11H2Test {

  private static final String MODULE = CaH2TestEnv.P11_MODULE;

  private static CaH2TestEnv env;

  private static CaMgmtTestServer httpServer;

  private static CaMgmtClient client;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(new CaH2TestEnv.Options().pkcs11(true));
    X509Cert mgmtCert = newCert();
    httpServer = new CaMgmtTestServer(env.caManager(), mgmtCert, mgmtCert);
    client = new CaMgmtClient();
    client.init(null, httpServer.url());

    P11Module module = env.securities().p11CryptServiceFactory().getP11Module(MODULE);
    P11Slot slot = module.getSlot(module.getSlotIdForIndex(0));
    slot.generateKeyPair(KeySpec.P256,
        new PKCS11KeyPairSpec().token(true).label("client-info-key").signVerify(true));
  }

  @AfterClass
  public static void shutdown() {
    if (httpServer != null) {
      httpServer.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void tokenInfo() throws Exception {
    String modules = client.getTokenInfoP11(MODULE, null, false);
    Assert.assertTrue(modules, modules.contains("module: " + MODULE));

    String details = client.getTokenInfoP11(MODULE, 0, true);
    Assert.assertTrue(details, details.contains("client-info-key"));

    Assert.assertThrows(CaMgmtException.class,
        () -> client.getTokenInfoP11("unknown-module", null, false));
  }

  private static X509Cert newCert() throws Exception {
    char[] password = "CHANGEIT".toCharArray();
    byte[] keystore = KeyUtil.generateX509KeyPair3(KeySpec.P256,
        new KeystoreGenerationParameters(password)).keystore();
    try (InputStream in = new ByteArrayInputStream(keystore)) {
      return X509KeypairWithCert.fromPKCS12Keystore(in, password, null, password,
          (X509Cert) null).certChain()[0];
    }
  }

}
