// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.certprofile.xijson.CertprofileFactoryImpl;
import org.xipki.ca.server.CaIdNameMap;
import org.xipki.ca.server.CaServerConf;
import org.xipki.ca.server.CertPublisherFactoryRegister;
import org.xipki.ca.server.CertprofileFactoryRegister;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.codec.json.JsonBuilder;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.pkix.cert.CertVariant;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.misc.NameId;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * A CA system with the CA configuration in files ({@code FileCaConfStore}): the configuration
 * of the CA of {@link CaH2TestEnv} is exported ({@code exportConf}), unpacked, and a second CA
 * system is started with these files and the same certificate store.
 *
 * @author Lijun Liao (xipki)
 */
public class FileCaConfH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static CaManagerImpl fileCaManager;

  private static BigInteger good;

  private static BigInteger revoked;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    CaManagerImpl caManager = env.caManager();
    good = issue(caManager, "file-good.example.org");
    revoked = issue(caManager, "file-revoked.example.org");
    caManager.revokeCertificate(CA, revoked, CrlReason.KEY_COMPROMISE, null);

    Path confDir = env.workDir().resolve("exported-caconf");
    try (InputStream zip = caManager.exportConf(List.of(CA))) {
      unzip(zip, confDir);
    }
    // the export has no IDs (by design), the files need those of the certificate store
    addIds(confDir.resolve("caconf.json"), caManager.idNameMap());

    // shard id 1: another instance on the same certificate store
    Path serverConf = env.workDir().resolve("ca-file.json");
    Files.writeString(serverConf, "{\"master\": true, \"noLock\": true, \"shardId\": 1,\n"
        + "  \"caConfFiles\": [\"" + jsonPath(confDir.resolve("caconf.json")) + "\"],\n"
        + "  \"datasources\": [{\"name\": \"ca\", \"conf\": {\"file\": \""
        + jsonPath(env.caDbConf()) + "\"}}],\n"
        + "  \"audit\": {\"type\": \"noop\"}}\n");

    fileCaManager = newManager(serverConf, "file-ca");
  }

  @AfterClass
  public static void shutdown() {
    if (fileCaManager != null) {
      fileCaManager.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void caIsStartedFromTheFiles() {
    Assert.assertEquals(CaSystemStatus.STARTED_AS_MASTER, fileCaManager.getCaSystemStatus());
    Assert.assertTrue(fileCaManager.getSuccessfulCaNames().contains(CA));
    Assert.assertEquals(CertVariant.ofX509(env.caCert()), fileCaManager.getCaCerts(CA).get(0));
    Assert.assertTrue(fileCaManager.getCertprofileNames().contains(CaH2TestEnv.PROFILE_TLS));
  }

  @Test
  public void certificatesOfTheStoreAreVisible() throws Exception {
    Assert.assertFalse(fileCaManager.getCert(CA, good).isRevoked());
    Assert.assertEquals(CrlReason.KEY_COMPROMISE,
        fileCaManager.getCert(CA, revoked).revInfo().reason());
  }

  @Test
  public void issueAndRevoke() throws Exception {
    BigInteger serial = issue(fileCaManager, "file-new.example.org");
    // the certificate is in the shared store
    Assert.assertNotNull(env.caManager().getCert(CA, serial));

    fileCaManager.revokeCertificate(CA, serial, CrlReason.KEY_COMPROMISE, null);
    Assert.assertTrue(env.caManager().getCert(CA, serial).isRevoked());
  }

  @Test
  public void configurationIsReadOnly() {
    Assert.assertThrows(CaMgmtException.class, () -> fileCaManager.addCertprofile(
        new CertprofileEntry(new NameId(null, "new-profile"), "xijson", "{}")));
  }

  @Test
  public void configurationErrorIsReportedAsError() throws Exception {
    // the exported configuration without IDs is invalid as file configuration
    Path confDir = env.workDir().resolve("exported-caconf-noids");
    try (InputStream zip = env.caManager().exportConf(List.of(CA))) {
      unzip(zip, confDir);
    }
    Path serverConf = env.workDir().resolve("ca-file-invalid.json");
    Files.writeString(serverConf, "{\"master\": true, \"noLock\": true, \"shardId\": 2,\n"
        + "  \"caConfFiles\": [\"" + jsonPath(confDir.resolve("caconf.json")) + "\"],\n"
        + "  \"datasources\": [{\"name\": \"ca\", \"conf\": {\"file\": \""
        + jsonPath(env.caDbConf()) + "\"}}],\n"
        + "  \"audit\": {\"type\": \"noop\"}}\n");
    CaManagerImpl manager = newManager(serverConf, "file-ca-invalid");
    try {
      Assert.assertEquals(CaSystemStatus.ERROR, manager.getCaSystemStatus());
    } finally {
      manager.close();
    }
  }

  private static CaManagerImpl newManager(Path serverConf, String dirName) throws Exception {
    Path workDir = Files.createDirectories(env.workDir().resolve(dirName));
    CaManagerImpl manager = new CaManagerImpl(workDir.toString());
    manager.setSecurityFactory(env.securities().securityFactory());
    CertprofileFactoryRegister profileRegister = new CertprofileFactoryRegister();
    profileRegister.registFactory(new CertprofileFactoryImpl());
    manager.setCertprofileFactoryRegister(profileRegister);
    manager.setCertPublisherFactoryRegister(new CertPublisherFactoryRegister());
    manager.setKeyPairGeneratorFactories(Collections.emptySet());
    manager.setCaServerConf(CaServerConf.readConfFromFile(serverConf.toString()));
    manager.startCaSystem();
    return manager;
  }

  private static BigInteger issue(CaManagerImpl caManager, String commonName) throws Exception {
    X509Cert cert = X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null).cert());
    return cert.serialNumber();
  }

  private static void addIds(Path caconfFile, CaIdNameMap idNameMap) throws Exception {
    JsonMap root = JsonParser.parseMap(caconfFile, false);
    JsonList profiles = root.getList("profiles");
    for (int i = 0; i < profiles.size(); i++) {
      JsonMap profile = (JsonMap) profiles.getAt(i);
      profile.put("id", idNameMap.getCertprofile(profile.getString("name")).id());
    }
    JsonList cas = root.getList("cas");
    for (int i = 0; i < cas.size(); i++) {
      JsonMap ca = (JsonMap) cas.getAt(i);
      ca.put("id", idNameMap.getCa(ca.getString("name")).id());
    }
    Files.writeString(caconfFile, JsonBuilder.toPrettyJson(root));
  }

  private static void unzip(InputStream zipStream, Path dir) throws Exception {
    Files.createDirectories(dir);
    try (ZipInputStream zip = new ZipInputStream(zipStream)) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        Path file = dir.resolve(entry.getName()).normalize();
        Assert.assertTrue("zip entry inside the directory", file.startsWith(dir));
        if (entry.isDirectory()) {
          Files.createDirectories(file);
        } else {
          Files.createDirectories(file.getParent());
          Files.write(file, zip.readAllBytes());
        }
      }
    }
  }

  private static String jsonPath(Path path) {
    return path.toAbsolutePath().toString().replace("\\", "/");
  }

}
