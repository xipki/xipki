// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.KeyStore;
import java.time.Instant;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.xipki.codec.util.ConfPairs;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.ApiException;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.service.*;
import org.xipki.mgmt.web.service.ProfileCapabilities.CertLevel;

/**
 * Domain contract tests.
 *
 * @author palos
 */
class DomainContractsTest {
  @Test
  void onlineSubCaSubjectMustMatchProfileOrderBeforeIssuance() throws Exception {
    String conf =
        "{\"certLevel\":\"SubCA\",\"subject\":[{\"type\":\"country\"},"
            + "{\"type\":\"organization\"},{\"type\":\"commonName\"}]}";
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) ->
                    new CertprofileEntry(new NameId(null, "sub"), "xijson", conf));
    var wrong = new X500Principal("C=CN,O=XiPKI Test,CN=child");
    var error =
        assertThrows(
            ApiException.class, () -> CaEnrollmentSubjectOrder.requireMatch(manager, "sub", wrong));
    assertEquals(400, error.status());
    assertTrue(error.getMessage().contains("subject order"));
    assertDoesNotThrow(
        () ->
            CaEnrollmentSubjectOrder.requireMatch(
                manager, "sub", new X500Principal("CN=child,O=XiPKI Test,C=CN")));
  }

  @Test
  void subjectOrderUsesLegacyAndExplicitProfileOrder() throws Exception {
    var confs =
        Map.of(
            "legacy",
                "{\"subject\":{\"rdns\":[{\"type\":{\"oid\":\"2.5.4.6\"}},"
                    + "{\"type\":{\"oid\":\"2.5.4.10\"}},{\"type\":{\"oid\":\"2.5.4.3\"}}]}}",
            "custom",
                "{\"keepSubjectOrder\":true,\"subject\":[{\"type\":\"commonName\"},"
                    + "{\"type\":\"organization\"},{\"type\":\"country\"}]}");
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) ->
                    new CertprofileEntry(
                        new NameId(null, (String) args[0]), "xijson", confs.get(args[0])));
    assertDoesNotThrow(
        () ->
            CaEnrollmentSubjectOrder.requireMatch(
                manager, "legacy", new X500Principal("CN=child,O=XiPKI Test,C=CN")));
    assertDoesNotThrow(
        () ->
            CaEnrollmentSubjectOrder.requireMatch(
                manager, "custom", new X500Principal("C=CN,O=XiPKI Test,CN=child")));
    assertThrows(
        ApiException.class,
        () ->
            CaEnrollmentSubjectOrder.requireMatch(
                manager, "custom", new X500Principal("CN=child,O=XiPKI Test,C=CN")));
  }

  @Test
  void fixedSubjectValueFailsBeforeIssuance() {
    String conf =
        "{\"subject\":[{\"type\":\"country\",\"value\":\"CN\"},{\"type\":\"commonName\"}]}";
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) ->
                    new CertprofileEntry(new NameId(null, "fixed"), "xijson", conf));
    var error =
        assertThrows(
            ApiException.class,
            () ->
                CaEnrollmentSubjectOrder.requireMatch(
                    manager, "fixed", new X500Principal("CN=child")));
    assertEquals(400, error.status());
    assertTrue(error.getMessage().contains("fixed"));
  }

  @Test
  void configuredCaRdnOrderAndRepeatedFieldsAreChecked() throws Exception {
    String conf =
        "{\"subject\":[{\"type\":\"country\"},{\"type\":\"organization\","
            + "\"maxOccurs\":2},{\"type\":\"commonName\"}]}";
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) ->
                    new CertprofileEntry(new NameId(null, "sub"), "xijson", conf));
    var subject = new X500Principal("CN=child,O=Two,O=One,C=CN");
    assertDoesNotThrow(() -> CaEnrollmentSubjectOrder.requireMatch(manager, "sub", subject));
    var customOrder = CaEnrollmentSubjectOrder.parseOrder("2.5.4.3,2.5.4.10,2.5.4.6");
    assertThrows(
        ApiException.class,
        () -> CaEnrollmentSubjectOrder.requireMatch(manager, "sub", subject, customOrder));
    assertThrows(
        IllegalArgumentException.class,
        () -> CaEnrollmentSubjectOrder.parseOrder("2.5.4.3,2.5.4.3"));
  }

  @Test
  void missingCaKeypairGeneratorHasActionableConflict() throws Exception {
    var ca = new CaEntry(new BaseCaInfo("PKCS12", null), new NameId(null, "child"), "");
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) -> ca);
    var error =
        assertThrows(
            ApiException.class,
            () -> CertificateMaterial.requireKeypairGenerator(manager, "child"));
    assertEquals(409, error.status());
    assertTrue(error.getMessage().contains("keypair generator"));
    ca.getBase().setKeypairGenNames(List.of("software"));
    assertDoesNotThrow(() -> CertificateMaterial.requireKeypairGenerator(manager, "child"));
  }

  @Test
  void profileCapabilitiesComeFromConfigurationAndRejectInvalidPathLength() {
    var profiles =
        Map.of(
            "sub",
                "{\"certLevel\":\"SubCA\",\"extensions\":[{\"type\":\"BasicConstraints\","
                    + "\"basicConstraints\":{\"pathLen\":0}}],\"keyAlgorithms\":[\"RSA2048\"]}",
            "bad", "{\"certLevel\":\"SubCA\",\"basicConstraints\":{\"pathLen\":2147483648}}",
            "decimal", "{\"certLevel\":\"SubCA\",\"basicConstraints\":{\"pathLen\":1.0}}",
            "root", "{\"certLevel\":\"RootCA\"}");
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) -> {
                  if (!method.getName().equals("getCertprofile")) {
                    throw new UnsupportedOperationException();
                  }
                  String name = (String) args[0];
                  return profiles.containsKey(name)
                      ? new CertprofileEntry(new NameId(null, name), "xijson", profiles.get(name))
                      : null;
                });
    var service = new ProfileCapabilitiesService(manager);
    var sub = service.describe("sub");
    assertEquals(CertLevel.SUB_CA, sub.level());
    assertEquals(0, sub.pathLenConstraint());
    assertEquals(Set.of("RSA2048"), sub.keyAlgorithms());
    assertEquals(CertLevel.ROOT_CA, service.describe("root").level());
    for (var name : List.of("bad", "decimal", "missing")) {
      assertEquals(CertLevel.UNKNOWN, service.describe(name).level());
    }
  }

  @Test
  void configurationDefaultsInactiveAndChangesDoNotReplaceOmittedSigner() {
    var mapper = new CaConfigurationMapper();
    assertEquals(CaStatus.inactive, mapper.create("PKCS12", null, null).getStatus());
    var config = new CaConfigurationRequest();
    config.status = "inactive";
    config.serialNoLen = 16;
    config.permissions = List.of("enroll_cert");
    var change = mapper.change("alpha", config);
    assertNull(change.getSignerConf());
    assertNull(change.getSignerType());
    assertEquals(16, change.getSerialNoLen());
    config.signerConf = "keystore=file:/etc/passwd,password=secret";
    assertThrows(IllegalArgumentException.class, () -> mapper.change("alpha", config));
    config.signerConf = null;
    config.permissions = List.of("1073741824");
    assertThrows(IllegalArgumentException.class, () -> mapper.change("alpha", config));
  }

  @Test
  void generatedPkcs12CanBeReimportedAndRejectsWrongPasswordAndFileModule() throws Exception {
    var service = new CaKeyMaterialService();
    var key = new CaKeyRequest();
    key.mode = "generate";
    key.algorithm = "EC_P256";
    var material = service.prepare(key, null, true);
    var pairs = new ConfPairs(material.conf());
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(
        new ByteArrayInputStream(Base64.getDecoder().decode(pairs.value("keystore").substring(7))),
        pairs.value("password").toCharArray());
    assertNotNull(store.getKey("main", pairs.value("password").toCharArray()));
    key.mode = "pkcs12";
    key.pkcs12 = pairs.value("keystore").substring(7);
    key.password = "incorrect";
    assertThrows(IllegalArgumentException.class, () -> service.prepare(key, null, true));
    key.password = pairs.value("password");
    assertEquals("PKCS12", service.prepare(key, null, true).type());
    key.mode = "pkcs11";
    key.module = "file:/etc/passwd";
    key.slotIndex = 0;
    key.keyLabel = "ca";
    assertThrows(IllegalArgumentException.class, () -> service.prepare(key, null, true));
  }

  @Test
  void certificateSerialAndTimesAreStrictBeforeRemoteMutation() {
    assertThrows(IllegalArgumentException.class, () -> CertificateMaterial.serial("-1"));
    assertThrows(IllegalArgumentException.class, () -> CertificateMaterial.serial("0"));
    assertEquals(new BigInteger("a1", 16), CertificateMaterial.serial("a1"));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificateMaterial.time("2026-10-27T00:00:00+08:00"));
    assertThrows(
        IllegalArgumentException.class, () -> CertificateMaterial.range(Instant.MAX, Instant.MIN));
  }
}
