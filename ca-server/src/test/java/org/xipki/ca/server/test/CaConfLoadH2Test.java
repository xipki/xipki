// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.certprofile.xijson.CertprofileFactoryImpl;
import org.xipki.ca.server.CaServerConf;
import org.xipki.ca.server.CertPublisherFactoryRegister;
import org.xipki.ca.server.CertprofileFactoryRegister;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.util.X509Util;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

/**
 * Export and load of the CA configuration ({@code exportConf}, {@code loadConf}): the
 * configuration of the CA of {@link CaH2TestEnv} is loaded into a second CA system with an
 * empty CA configuration database and the same certificate store.
 *
 * @author Lijun Liao (xipki)
 */
public class CaConfLoadH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static CaManagerImpl loaded;

  private static byte[] exported;

  private static BigInteger revoked;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    revoked = issue(env.caManager(), "load-revoked.example.org");
    env.caManager().revokeCertificate(CA, revoked, CrlReason.KEY_COMPROMISE, null);
    try (InputStream in = env.caManager().exportConf(List.of(CA))) {
      exported = in.readAllBytes();
    }

    Path caconf = env.newDatabase("caconf-load", true);
    Path serverConf = env.workDir().resolve("ca-load.json");
    Files.writeString(serverConf, "{\"master\": true, \"noLock\": true, \"shardId\": 1,\n"
        + "  \"datasources\": [\n"
        + "    {\"name\": \"ca\", \"conf\": {\"file\": \"" + jsonPath(env.caDbConf()) + "\"}},\n"
        + "    {\"name\": \"caconf\", \"conf\": {\"file\": \"" + jsonPath(caconf) + "\"}}],\n"
        + "  \"audit\": {\"type\": \"noop\"}}\n");

    Path workDir = Files.createDirectories(env.workDir().resolve("load-ca"));
    loaded = new CaManagerImpl(workDir.toString());
    loaded.setSecurityFactory(env.securities().securityFactory());
    CertprofileFactoryRegister profileRegister = new CertprofileFactoryRegister();
    profileRegister.registFactory(new CertprofileFactoryImpl());
    loaded.setCertprofileFactoryRegister(profileRegister);
    loaded.setCertPublisherFactoryRegister(new CertPublisherFactoryRegister());
    loaded.setKeyPairGeneratorFactories(Collections.emptySet());
    loaded.setCaServerConf(CaServerConf.readConfFromFile(serverConf.toString()));
    loaded.startCaSystem();
    Assert.assertEquals(CaSystemStatus.STARTED_AS_MASTER, loaded.getCaSystemStatus());
    Assert.assertTrue("no CA before loading", loaded.getCaNames().isEmpty());

    loaded.loadConf(exported);
  }

  @AfterClass
  public static void shutdown() {
    if (loaded != null) {
      loaded.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void configurationIsLoaded() {
    Assert.assertTrue(loaded.getSuccessfulCaNames().contains(CA));
    Assert.assertEquals(CertVariant.ofX509(env.caCert()), loaded.getCaCerts(CA).get(0));
    Assert.assertEquals(env.caManager().getCertprofileNames(), loaded.getCertprofileNames());
    Assert.assertEquals(CaH2TestEnv.PROFILE_TLS,
        loaded.getCertprofilesForCa(CA).iterator().next().profileName());
  }

  @Test
  public void loadedCaWorksOnTheSameStore() throws Exception {
    Assert.assertTrue(loaded.getCert(CA, revoked).isRevoked());
    BigInteger serial = issue(loaded, "load-new.example.org");
    Assert.assertNotNull(env.caManager().getCert(CA, serial));
  }

  @Test
  public void loadingTwiceIsRejected() {
    Assert.assertThrows(CaMgmtException.class, () -> loaded.loadConf(exported));
  }

  private static BigInteger issue(CaManagerImpl caManager, String commonName) throws Exception {
    return X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null).cert()).serialNumber();
  }

  private static String jsonPath(Path path) {
    return path.toAbsolutePath().toString().replace("\\", "/");
  }

}
