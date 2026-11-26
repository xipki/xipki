// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.ca.CaDomain.CertListOrderBy;
import org.xipki.mgmt.web.ca.CaDomain.CrlReason;

/** Contract tests for the boundary between Console and XiPKI's official management client. */
class OfficialCaMgmtClientAdapterTest {
  @Test
  void nameOnlyResourceIndexesComeFromTheOfficialClient() throws Exception {
    var adapter = new OfficialCaMgmtClientAdapter(new ResourceIndexClient());

    assertEquals(Set.of("profile"), adapter.getCertprofileNames());
    assertEquals(Set.of("generator"), adapter.getKeypairGenNames());
    assertEquals(Set.of("publisher"), adapter.getPublisherNames());
    assertEquals(Set.of("requestor"), adapter.getRequestorNames());
    assertEquals(Set.of("signer"), adapter.getSignerNames());
    assertEquals(Set.of("alias"), adapter.getCaAliasNames());
    assertEquals(Set.of("alias"), adapter.getAliasesForCa("business-ca"));
    assertEquals("business-ca", adapter.getCaNameForAlias("alias"));
    assertEquals(Set.of("publisher"), adapter.getPublisherNamesForCa("business-ca"));
    assertEquals(Map.of("VERSION", "1"), adapter.getDbSchemas());
    assertEquals(Set.of("PKCS12"), adapter.getSupportedSignerTypes());
    assertEquals(Set.of("xijson"), adapter.getSupportedCertprofileTypes());
    assertEquals(Set.of("ocsp"), adapter.getSupportedPublisherTypes());
  }

  @Test
  void simpleControlMutationsUseTheOfficialClient() throws Exception {
    var client = new MutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.unlockCa();
    adapter.notifyCaChange();
    adapter.restartCa("business-ca");
    adapter.restartCaSystem();
    adapter.addCaAlias("production", "business-ca");
    adapter.removeCaAlias("old");
    adapter.addDbSchema("KEY", "one");
    adapter.changeDbSchema("KEY", "two");
    adapter.removeDbSchema("KEY");
    adapter.republishCertificates("business-ca", List.of("ocsp"), 3);

    assertEquals(
        List.of(
            "unlock",
            "notify",
            "restart:business-ca",
            "restart-system",
            "add-alias:production:business-ca",
            "remove-alias:old",
            "add-schema:KEY:one",
            "change-schema:KEY:two",
            "remove-schema:KEY",
            "republish:business-ca:ocsp:3"),
        client.actions);
  }

  @Test
  void certificateInventoryUsesOfficialTypesWithoutChangingTheConsoleContract() throws Exception {
    var client = new CertificateListClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);
    Instant from = Instant.parse("2026-01-01T00:00:00Z");
    Instant to = Instant.parse("2027-01-01T00:00:00Z");

    var result =
        adapter.listCertificates(
            "business-ca", null, from, to, CertListOrderBy.NOT_BEFORE_DESC, 100);

    assertEquals("business-ca", client.caName);
    assertEquals(0, client.subject.size(), "An empty DN preserves XiPKI 7 match-all behavior");
    assertEquals(org.xipki.ca.api.mgmt.CertListOrderBy.NOT_BEFORE_DESC, client.orderBy);
    assertEquals(100, client.limit);
    assertEquals(BigInteger.valueOf(42), result.get(0).getSerialNumber());
    assertEquals("CN=Issued", result.get(0).getSubject());
    assertEquals(CrlReason.KEY_COMPROMISE, result.get(0).getRevocationInfo().getReason());
  }

  @Test
  void certificateLifecycleUsesOfficialTypesWithoutChangingTheConsoleContract() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    var certificate = Crypto.placeholder(generator.generateKeyPair());
    var client = new CertificateLifecycleClient(certificate.getEncoded());
    var adapter = new OfficialCaMgmtClientAdapter(client);
    Instant invalidityTime = Instant.parse("2026-06-01T00:00:00Z");

    var result = adapter.getCert("business-ca", BigInteger.valueOf(42));
    adapter.revokeCertificate(
        "business-ca", BigInteger.valueOf(42), CrlReason.KEY_COMPROMISE, invalidityTime);
    adapter.unsuspendCertificate("business-ca", BigInteger.valueOf(42));
    adapter.removeCertificate("business-ca", BigInteger.valueOf(42));

    assertEquals("tls-server", result.getCertprofile());
    assertEquals(certificate.getSerialNumber(), result.getCert().getCert().getSerialNumber());
    assertEquals(CrlReason.KEY_COMPROMISE, result.getRevInfo().getReason());
    assertEquals(
        List.of(
            "revoke:business-ca:2a:KEY_COMPROMISE:2026-06-01T00:00:00Z",
            "unsuspend:business-ca:2a",
            "remove:business-ca:2a"),
        client.actions);
  }

  @Test
  void csrCertificateIssuanceUsesTheOfficialClientWithoutChangingRequestOrCertificate()
      throws Exception {
    byte[] encodedCertificate =
        Base64.getDecoder().decode(CaMutationClient.CA_CERTIFICATE);
    var client = new CertificateIssuanceClient(encodedCertificate);
    var adapter = new OfficialCaMgmtClientAdapter(client);
    byte[] csr = new byte[] {1, 3, 5, 7};
    Instant notBefore = Instant.parse("2026-11-05T00:00:00Z");
    Instant notAfter = Instant.parse("2027-11-05T00:00:00Z");

    var result =
        adapter.generateCertificate("business-ca", "tls-server", csr, notBefore, notAfter);

    assertEquals("business-ca", client.caName);
    assertEquals("tls-server", client.profileName);
    assertArrayEquals(csr, client.encodedCsr);
    assertEquals(notBefore, client.notBefore);
    assertEquals(notAfter, client.notAfter);
    assertArrayEquals(encodedCertificate, result.getEncoded());
  }

  @Test
  void generatedKeyCertificateIssuanceUsesTheOfficialClientWithoutChangingBytes()
      throws Exception {
    byte[] encodedCertificate =
        Base64.getDecoder().decode(CaMutationClient.CA_CERTIFICATE);
    byte[] encodedKey = new byte[] {2, 4, 6, 8};
    var client = new CertificateIssuanceClient(encodedCertificate, encodedKey);
    var adapter = new OfficialCaMgmtClientAdapter(client);
    Instant notBefore = Instant.parse("2026-11-05T00:00:00Z");
    Instant notAfter = Instant.parse("2027-11-05T00:00:00Z");

    var result =
        adapter.generateKeyCert(
            "business-ca", "tls-server", "CN=service.example", notBefore, notAfter);

    assertEquals("business-ca", client.caName);
    assertEquals("tls-server", client.profileName);
    assertEquals("CN=service.example", client.subject);
    assertEquals(notBefore, client.notBefore);
    assertEquals(notAfter, client.notAfter);
    assertArrayEquals(encodedKey, result.getKey());
    assertArrayEquals(encodedCertificate, result.getCert());
  }

  @Test
  void crossCertificateIssuanceUsesTheOfficialClientWithoutChangingRequestOrCertificate()
      throws Exception {
    byte[] encodedCertificate =
        Base64.getDecoder().decode(CaMutationClient.CA_CERTIFICATE);
    var client = new CertificateIssuanceClient(encodedCertificate);
    var adapter = new OfficialCaMgmtClientAdapter(client);
    byte[] csr = new byte[] {1, 2, 3, 4};
    byte[] targetCertificate = new byte[] {5, 6, 7, 8};
    Instant notBefore = Instant.parse("2026-11-05T00:00:00Z");
    Instant notAfter = Instant.parse("2027-11-05T00:00:00Z");

    var result =
        adapter.generateCrossCertificate(
            "business-ca",
            "cross-ca",
            csr,
            targetCertificate,
            notBefore,
            notAfter);

    assertEquals("business-ca", client.caName);
    assertEquals("cross-ca", client.profileName);
    assertArrayEquals(csr, client.encodedCsr);
    assertArrayEquals(targetCertificate, client.encodedTargetCertificate);
    assertEquals(notBefore, client.notBefore);
    assertEquals(notAfter, client.notAfter);
    assertArrayEquals(encodedCertificate, result.getEncoded());
  }

  @Test
  void crlOperationsUseTheOfficialClientWithoutChangingDownloadedBytes() throws Exception {
    var client = new CrlClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var generated = adapter.generateCrlOnDemand("business-ca");
    var numbered = adapter.getCrl("business-ca", 7);
    var current = adapter.getCurrentCrl("business-ca");

    assertEquals(
        List.of("generate:business-ca", "get:business-ca:7", "current:business-ca"),
        client.actions);
    assertArrayEquals(client.encodedCrl, generated.getEncoded());
    assertArrayEquals(client.encodedCrl, numbered.getEncoded());
    assertArrayEquals(client.encodedCrl, current.getEncoded());
    assertEquals(BigInteger.ONE, current.getCrlNumber());
  }

  @Test
  void caDetailsComeFromTheOfficialClientWithoutChangingTheConsoleContract() throws Exception {
    var client = new CaDetailClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getCa("business-ca");

    assertEquals("business-ca", client.requestedName);
    assertEquals(23, result.getIdent().id());
    assertEquals("business-ca", result.getIdent().name());
    assertEquals("password=secret", result.getSignerConf());
    assertEquals("PKCS12", result.getBase().getSignerType());
    assertEquals("365d", result.getBase().getMaxValidity().toString());
    assertEquals(9, result.getBase().getNextCrlNo());
    assertEquals(
        List.of("https://ca.example.test/ca.crt"),
        result.getBase().getCaUris().getCacertUris());
  }

  @Test
  void certificateProfileDetailsComeFromTheOfficialClient() throws Exception {
    var client = new ResourceDetailClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getCertprofile("tls-server");

    assertEquals("tls-server", client.requestedProfile);
    assertEquals(31, result.getIdent().id());
    assertEquals("tls-server", result.getIdent().name());
    assertEquals("xijson", result.getType());
    assertEquals("profile-conf", result.getConf());
  }

  @Test
  void publisherDetailsComeFromTheOfficialClient() throws Exception {
    var client = new ResourceDetailClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getPublisher("ocsp-publisher");

    assertEquals("ocsp-publisher", client.requestedPublisher);
    assertEquals(32, result.getIdent().id());
    assertEquals("ocsp-publisher", result.getIdent().name());
    assertEquals("ocsp", result.getType());
    assertEquals("publisher-conf", result.getConf());
  }

  @Test
  void requestorDetailsComeFromTheOfficialClient() throws Exception {
    var client = new ResourceDetailClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getRequestor("gateway-requestor");

    assertEquals("gateway-requestor", client.requestedRequestor);
    assertEquals(33, result.getIdent().id());
    assertEquals("gateway-requestor", result.getIdent().name());
    assertEquals("cert", result.getType());
    assertEquals("requestor-conf", result.getConf());
  }

  @Test
  void signerDetailsComeFromTheOfficialClient() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    var certificate = Crypto.placeholder(generator.generateKeyPair());
    var client = new ResourceDetailClient();
    client.signerCertificate = org.xipki.pkix.util.X509Util.parseCert(certificate.getEncoded());
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getSigner("audit-signer");

    assertEquals("audit-signer", client.requestedSigner);
    assertEquals("pkcs12", result.getType());
    assertEquals("signer-conf", result.getConf());
    assertEquals(
        Base64.getEncoder().encodeToString(certificate.getEncoded()), result.getBase64Cert());
  }

  @Test
  void keypairGeneratorDetailsComeFromTheOfficialClient() throws Exception {
    var client = new ResourceDetailClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getKeypairGen("software-generator");

    assertEquals("software-generator", client.requestedKeypairGenerator);
    assertEquals("software-generator", result.getName());
    assertEquals("software", result.getType());
    assertEquals("keyspec=RSA/2048", result.getConf());
  }

  @Test
  void keypairGeneratorLifecycleUsesTheOfficialClient() throws Exception {
    var client = new ResourceMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.addKeypairGen(
        new CaDomain.KeypairGenEntry(
            "software-generator", "SOFTWARE", "keyspec=RSA/2048"));
    adapter.changeKeypairGen("software-generator", "SOFTWARE", "keyspec=EC/P-256");
    adapter.removeKeypairGen("software-generator");

    assertEquals(
        List.of(
            "add-keypair-generator:software-generator:software:keyspec=RSA/2048",
            "change-keypair-generator:software-generator:SOFTWARE:keyspec=EC/P-256",
            "remove-keypair-generator:software-generator"),
        client.actions);
  }

  @Test
  void caCreationUsesTheOfficialClientWithoutLosingConfiguration() throws Exception {
    var base =
        new CaDomain.BaseCaInfo("PKCS12", new CaDomain.Permissions(List.of("enroll_cert")));
    base.setStatus(CaDomain.CaStatus.inactive);
    base.setMaxValidity(org.xipki.util.conf.Validity.getInstance("730d"));
    base.setValidityMode(CaDomain.ValidityMode.CUTOFF);
    base.setNextCrlNo(12);
    base.setSnSize(16);
    base.setNumCrls(24);
    base.setExpirationPeriod(30);
    base.setKeepExpiredCertDays(90);
    base.setSaveCert(true);
    base.setSaveKeypair(true);
    base.setKeypairGenNames(List.of("software-generator"));
    base.setCrlSignerName("crl-signer");
    base.setCaUris(
        new CaDomain.CaUris(
            List.of("https://ca.example.test/ca.crt"),
            List.of("https://ocsp.example.test"),
            List.of("https://ca.example.test/ca.crl"),
            null));
    base.setCrlControl(new CaDomain.CrlControl("interval.hours=24"));
    base.setCtlogControl(
        new CaDomain.CtlogControl("enabled=false,servers=https://ct.example.test"));
    base.setRevokeSuspendedControl(
        new CaDomain.RevokeSuspendedControl("enabled=true,unchangedSince=7d"));
    base.setExtraControl(new org.xipki.codec.util.ConfPairs("mode=strict"));
    var entry =
        new CaDomain.CaEntry(
            base,
            new CaDomain.NameId(null, "business-ca"),
            "keystore=file:ca.p12,password=secret");
    var certificate =
        Crypto.X509Util.parseCert(Base64.getDecoder().decode(CaMutationClient.CA_CERTIFICATE));
    entry.setCert(certificate);
    entry.setCertchain(List.of(certificate));
    var client = new CaMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.addCa(entry);

    var result = client.addedCa;
    assertEquals("business-ca", result.ident().name());
    assertEquals("PKCS12", result.base().signerType());
    assertEquals("730d", result.base().maxValidity().toString());
    assertEquals(org.xipki.ca.api.mgmt.CaStatus.inactive, result.base().status());
    assertEquals(
        org.xipki.ca.api.profile.ctrl.ValidityMode.CUTOFF, result.base().validityMode());
    assertEquals(12, result.base().nextCrlNo());
    assertEquals(16, result.base().snSize());
    assertEquals(24, result.base().numCrls());
    assertEquals(30, result.base().expirationPeriod());
    assertEquals(90, result.base().keepExpiredCertDays());
    assertEquals(true, result.base().isSaveCert());
    assertEquals(true, result.base().isSaveKeypair());
    assertEquals(1, result.base().permissions().value());
    assertEquals(List.of("software-generator"), result.base().keypairGenNames());
    assertEquals("crl-signer", result.base().crlSignerName());
    assertEquals(base.getCrlControl().getConf(), result.base().crlControl().getConf());
    assertEquals(base.getCtlogControl().getConf(), result.base().ctlogControl().getConf());
    assertEquals(
        base.getRevokeSuspendedControl().getConf(),
        result.base().revokeSuspendedControl().getConf());
    assertEquals("strict", result.base().extraControl().value("mode"));
    assertEquals(
        List.of("https://ca.example.test/ca.crt"), result.base().caUris().cacertUris());
    assertArrayEquals(certificate.getEncoded(), result.cert().getEncoded());
    assertEquals(1, result.certchain().size());
    assertEquals("keystore=file:ca.p12,password=secret", result.signerConf());
  }

  @Test
  void caChangesUseTheOfficialClientWithoutChangingNullSemantics() throws Exception {
    var change = new CaDomain.ChangeCaEntry(new CaDomain.NameId(null, "business-ca"));
    change.setStatus(CaDomain.CaStatus.active);
    change.setMaxValidity(org.xipki.util.conf.Validity.getInstance("365d"));
    change.setValidityMode(CaDomain.ValidityMode.BY_CA);
    change.setPermissions(List.of("enroll_cert", "revoke_cert"));
    change.setSerialNoLen(18);
    change.setNumCrls(12);
    change.setExpirationPeriod(14);
    change.setKeepExpiredCertDays(45);
    change.setSaveCert(true);
    change.setSaveKeypair(false);
    change.setKeypairGenNames(List.of("software-generator"));
    change.setCrlSignerName("crl-signer");
    change.setCrlControl("NULL");
    change.setCtlogControl("NULL");
    change.setRevokeSuspendedControl("NULL");
    change.setExtraControl("NULL");
    change.setCaUris(
        new CaDomain.CaUris(
            List.of("https://ca.example.test/ca.crt"), null, null, null));
    change.setSignerType("PKCS12");
    change.setSignerConf("keystore=file:replacement.p12,password=secret");
    change.setEncodedCert(new byte[] {1, 2, 3});
    change.setEncodedCertchain(List.of(new byte[] {4, 5}, new byte[] {6, 7}));
    var client = new CaMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.changeCa(change);

    var result = client.changedCa;
    assertEquals("business-ca", result.ident().name());
    assertEquals(org.xipki.ca.api.mgmt.CaStatus.active, result.status());
    assertEquals("365d", result.maxValidity().toString());
    assertEquals(org.xipki.ca.api.profile.ctrl.ValidityMode.BY_CA, result.validityMode());
    assertEquals(List.of("enroll_cert", "revoke_cert"), result.permissions());
    assertEquals(18, result.serialNoLen());
    assertEquals(12, result.numCrls());
    assertEquals("NULL", result.crlControl());
    assertEquals("NULL", result.ctlogControl());
    assertEquals("NULL", result.revokeSuspendedControl());
    assertEquals("NULL", result.extraControl());
    assertEquals("pkcs12", result.signerType());
    assertArrayEquals(new byte[] {1, 2, 3}, result.encodedCert());
    assertEquals(2, result.encodedCertchain().size());
  }

  @Test
  void caLifecycleUsesTheOfficialClientWithoutLosingRevocationMetadata() throws Exception {
    var client = new CaMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);
    Instant revokedAt = Instant.parse("2026-11-05T01:02:03Z");
    Instant invalidAt = Instant.parse("2026-11-04T01:02:03Z");

    adapter.revokeCa(
        "business-ca",
        new CaDomain.CertRevocationInfo(CrlReason.KEY_COMPROMISE, revokedAt, invalidAt));
    adapter.unrevokeCa("business-ca");
    adapter.removeCa("retired-ca");

    assertEquals(
        List.of(
            "revoke:business-ca:KEY_COMPROMISE:2026-11-05T01:02:03Z:2026-11-04T01:02:03Z",
            "unrevoke:business-ca",
            "remove:retired-ca"),
        client.actions);
  }

  @Test
  void caCertificateChainUsesTheOfficialClientWithoutChangingCertificateBytes()
      throws Exception {
    byte[] encodedCertificate =
        Base64.getDecoder().decode(CaMutationClient.CA_CERTIFICATE);
    var client = new CaCertificateClient(encodedCertificate);
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getCaCerts("business-ca");

    assertEquals("business-ca", client.requestedCa);
    assertEquals(2, result.size());
    assertArrayEquals(encodedCertificate, result.get(0).getEncoded());
    assertArrayEquals(encodedCertificate, result.get(1).getEncoded());
  }

  @Test
  void rootCaGenerationUsesTheOfficialClientWithoutChangingRequestOrCertificate()
      throws Exception {
    byte[] encodedCertificate =
        Base64.getDecoder().decode(CaMutationClient.CA_CERTIFICATE);
    var client = new RootCaClient(encodedCertificate);
    var adapter = new OfficialCaMgmtClientAdapter(client);
    var base =
        new CaDomain.BaseCaInfo("PKCS12", new CaDomain.Permissions(List.of("enroll_cert")));
    base.setMaxValidity(org.xipki.util.conf.Validity.getInstance("3650d"));
    var entry =
        new CaDomain.CaEntry(
            base,
            new CaDomain.NameId(null, "root-ca"),
            "keystore=file:root-ca.p12,password=secret");
    Instant notBefore = Instant.parse("2026-11-05T00:00:00Z");
    Instant notAfter = Instant.parse("2036-11-05T00:00:00Z");

    var result =
        adapter.generateRootCa(
            entry, "root-ca-profile", "CN=Root CA,O=Example", "0x1234", notBefore, notAfter);

    assertEquals("root-ca", client.caEntry.ident().name());
    assertEquals("PKCS12", client.caEntry.base().signerType());
    assertEquals("root-ca-profile", client.profile);
    assertEquals("CN=Root CA,O=Example", client.subject);
    assertEquals("0x1234", client.serialNumber);
    assertEquals(notBefore, client.notBefore);
    assertEquals(notAfter, client.notAfter);
    assertArrayEquals(encodedCertificate, result.getEncoded());
  }

  @Test
  void certificateProfileLifecycleUsesTheOfficialClient() throws Exception {
    var client = new ResourceMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.addCertprofile(
        new CaDomain.CertprofileEntry(
            new CaDomain.NameId(null, "tls-server"), "xijson", "profile-conf-one"));
    adapter.changeCertprofile("tls-server", "xijson", "profile-conf-two");
    adapter.removeCertprofile("tls-server");

    assertEquals(
        List.of(
            "add-profile:tls-server:xijson:profile-conf-one",
            "change-profile:tls-server:xijson:profile-conf-two",
            "remove-profile:tls-server"),
        client.actions);
  }

  @Test
  void publisherLifecycleUsesTheOfficialClient() throws Exception {
    var client = new ResourceMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.addPublisher(
        new CaDomain.PublisherEntry(
            new CaDomain.NameId(null, "ocsp-publisher"), "ocsp", "publisher-conf-one"));
    adapter.changePublisher("ocsp-publisher", "ocsp", "publisher-conf-two");
    adapter.removePublisher("ocsp-publisher");

    assertEquals(
        List.of(
            "add-publisher:ocsp-publisher:ocsp:publisher-conf-one",
            "change-publisher:ocsp-publisher:ocsp:publisher-conf-two",
            "remove-publisher:ocsp-publisher"),
        client.actions);
  }

  @Test
  void requestorLifecycleUsesTheOfficialClient() throws Exception {
    var client = new ResourceMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.addRequestor(
        new CaDomain.RequestorEntry(
            new CaDomain.NameId(null, "gateway-requestor"), "cert", "requestor-conf-one"));
    adapter.changeRequestor("gateway-requestor", "cert", "requestor-conf-two");
    adapter.removeRequestor("gateway-requestor");

    assertEquals(
        List.of(
            "add-requestor:gateway-requestor:cert:requestor-conf-one",
            "change-requestor:gateway-requestor:cert:requestor-conf-two",
            "remove-requestor:gateway-requestor"),
        client.actions);
  }

  @Test
  void signerLifecycleUsesTheOfficialClient() throws Exception {
    var client = new ResourceMutationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.addSigner(
        new CaDomain.SignerEntry(
            "audit-signer", "PKCS12", "signer-conf-one", "certificate-one"));
    adapter.changeSigner("audit-signer", "PKCS12", "signer-conf-two", "certificate-two");
    adapter.removeSigner("audit-signer");

    assertEquals(
        List.of(
            "add-signer:audit-signer:pkcs12:signer-conf-one:certificate-one",
            "change-signer:audit-signer:PKCS12:signer-conf-two:certificate-two",
            "remove-signer:audit-signer"),
        client.actions);
  }

  @Test
  void certificateProfileAssociationsUseTheOfficialClient() throws Exception {
    var client = new AssociationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getCertprofilesForCa("business-ca");
    adapter.addCertprofileToCa("tls-server:web,server", "business-ca");
    adapter.removeCertprofileFromCa("tls-server", "business-ca");

    var profile = result.iterator().next();
    assertEquals("business-ca", client.requestedProfileCa);
    assertEquals("tls-server", profile.getProfileName());
    assertEquals(Set.of("server", "web"), profile.getAliases());
    assertEquals(
        List.of(
            "add-profile:business-ca:tls-server:web,server",
            "remove-profile:business-ca:tls-server"),
        client.actions);
  }

  @Test
  void publisherAssociationsUseTheOfficialClient() throws Exception {
    var client = new AssociationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    adapter.addPublisherToCa("ocsp-publisher", "business-ca");
    adapter.removePublisherFromCa("ocsp-publisher", "business-ca");

    assertEquals(
        List.of(
            "add-publisher:business-ca:ocsp-publisher",
            "remove-publisher:business-ca:ocsp-publisher"),
        client.actions);
  }

  @Test
  void requestorAuthorizationsUseTheOfficialClientWithoutWideningScope() throws Exception {
    var client = new AssociationClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);

    var result = adapter.getRequestorsForCa("business-ca");
    adapter.addRequestorToCa(
        new CaDomain.CaHasRequestorEntry(
            new CaDomain.NameId(null, "gateway-requestor"),
            new CaDomain.Permissions(5),
            List.of("tls-server", "code-signing")),
        "business-ca");
    adapter.removeRequestorFromCa("gateway-requestor", "business-ca");

    var authorization = result.iterator().next();
    assertEquals("business-ca", client.requestedRequestorCa);
    assertEquals(41, authorization.getRequestorIdent().id());
    assertEquals("gateway-requestor", authorization.getRequestorIdent().name());
    assertEquals(3, authorization.getPermissions().getValue());
    assertEquals(Set.of("tls-server", "code-signing"), authorization.getProfiles());
    assertEquals(
        List.of(
            "add-requestor:business-ca:gateway-requestor:5:tls-server,code-signing",
            "remove-requestor:business-ca:gateway-requestor"),
        client.actions);
  }

  @Test
  void archiveAndTokenOperationsUseTheOfficialClient() throws Exception {
    var client = new ArchiveClient();
    var adapter = new OfficialCaMgmtClientAdapter(client);
    byte[] imported = new byte[] {1, 2, 3};

    adapter.loadConfAndClose(new ByteArrayInputStream(imported));
    byte[] exported;
    try (InputStream stream = adapter.exportConf(List.of("business-ca"))) {
      exported = stream.readAllBytes();
    }
    String tokenInfo = adapter.getTokenInfoP11("softhsm", 2, true);

    assertArrayEquals(imported, client.imported);
    assertEquals(List.of("business-ca"), client.exportedCaNames);
    assertArrayEquals(ArchiveClient.EXPORTED, exported);
    assertEquals("module=softhsm,slot=2,verbose=true", client.tokenRequest);
    assertEquals("token-info", tokenInfo);
  }

  /** Captures the final official-client operations that previously used the legacy transport. */
  private static final class ArchiveClient extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private static final byte[] EXPORTED = new byte[] {4, 5, 6};

    private byte[] imported;
    private List<String> exportedCaNames;
    private String tokenRequest;

    @Override
    public void loadConfAndClose(InputStream zippedConfStream) throws IOException {
      imported = zippedConfStream.readAllBytes();
    }

    @Override
    public InputStream exportConf(List<String> caNames) {
      exportedCaNames = List.copyOf(caNames);
      return new ByteArrayInputStream(EXPORTED);
    }

    @Override
    public String getTokenInfoP11(String moduleName, Integer slotIndex, boolean verbose) {
      tokenRequest =
          "module=" + moduleName + ",slot=" + slotIndex + ",verbose=" + verbose;
      return "token-info";
    }
  }

  private static final class ResourceIndexClient
      extends org.xipki.ca.mgmt.client.CaMgmtClient {
    @Override
    public Set<String> getCertprofileNames() {
      return Set.of("profile");
    }

    @Override
    public Set<String> getKeypairGenNames() {
      return Set.of("generator");
    }

    @Override
    public Set<String> getPublisherNames() {
      return Set.of("publisher");
    }

    @Override
    public Set<String> getRequestorNames() {
      return Set.of("requestor");
    }

    @Override
    public Set<String> getSignerNames() {
      return Set.of("signer");
    }

    @Override
    public Set<String> getCaAliasNames() {
      return Set.of("alias");
    }

    @Override
    public Set<String> getAliasesForCa(String caName) {
      return Set.of("alias");
    }

    @Override
    public String getCaNameForAlias(String aliasName) {
      return "business-ca";
    }

    @Override
    public Set<String> getPublisherNamesForCa(String caName) {
      return Set.of("publisher");
    }

    @Override
    public Map<String, String> getDbSchemas() {
      return Map.of("VERSION", "1");
    }

    @Override
    public Set<String> getSupportedSignerTypes() {
      return Set.of("PKCS12");
    }

    @Override
    public Set<String> getSupportedCertprofileTypes() {
      return Set.of("xijson");
    }

    @Override
    public Set<String> getSupportedPublisherTypes() {
      return Set.of("ocsp");
    }
  }

  private static final class MutationClient extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final List<String> actions = new ArrayList<>();

    @Override
    public void unlockCa() {
      actions.add("unlock");
    }

    @Override
    public void notifyCaChange() {
      actions.add("notify");
    }

    @Override
    public void restartCa(String caName) {
      actions.add("restart:" + caName);
    }

    @Override
    public void restartCaSystem() {
      actions.add("restart-system");
    }

    @Override
    public void addCaAlias(String aliasName, String caName) {
      actions.add("add-alias:" + aliasName + ":" + caName);
    }

    @Override
    public void removeCaAlias(String aliasName) {
      actions.add("remove-alias:" + aliasName);
    }

    @Override
    public void addDbSchema(String name, String value) {
      actions.add("add-schema:" + name + ":" + value);
    }

    @Override
    public void changeDbSchema(String name, String value) {
      actions.add("change-schema:" + name + ":" + value);
    }

    @Override
    public void removeDbSchema(String name) {
      actions.add("remove-schema:" + name);
    }

    @Override
    public void republishCertificates(String caName, List<String> publishers, int threads) {
      actions.add("republish:" + caName + ":" + String.join(",", publishers) + ":" + threads);
    }
  }

  private static final class CertificateListClient
      extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private String caName;
    private org.xipki.asn1.x500.X500Name subject;
    private org.xipki.ca.api.mgmt.CertListOrderBy orderBy;
    private int limit;

    @Override
    public List<org.xipki.ca.api.mgmt.CertListInfo> listCertificates(
        String caName,
        org.xipki.asn1.x500.X500Name subject,
        Instant validFrom,
        Instant validTo,
        org.xipki.ca.api.mgmt.CertListOrderBy orderBy,
        int limit) {
      this.caName = caName;
      this.subject = subject;
      this.orderBy = orderBy;
      this.limit = limit;
      var revocation =
          new org.xipki.pkix.cert.CertRevocationInfo(
              org.xipki.pkix.cert.CrlReason.KEY_COMPROMISE,
              Instant.parse("2026-06-01T00:00:00Z"));
      return List.of(
          new org.xipki.ca.api.mgmt.CertListInfo(
              BigInteger.valueOf(42), "CN=Issued", validFrom, validTo, revocation));
    }
  }

  private static final class CertificateLifecycleClient
      extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final List<String> actions = new ArrayList<>();
    private final org.xipki.ca.api.mgmt.CertWithRevocationInfo certificate;

    CertificateLifecycleClient(byte[] encodedCertificate) throws Exception {
      var cert = org.xipki.pkix.util.X509Util.parseCert(encodedCertificate);
      certificate = new org.xipki.ca.api.mgmt.CertWithRevocationInfo();
      certificate.setCert(new org.xipki.ca.api.CertWithDbId(cert));
      certificate.setCertprofile("tls-server");
      certificate.setRevInfo(
          new org.xipki.pkix.cert.CertRevocationInfo(
              org.xipki.pkix.cert.CrlReason.KEY_COMPROMISE,
              Instant.parse("2026-05-01T00:00:00Z")));
    }

    @Override
    public org.xipki.ca.api.mgmt.CertWithRevocationInfo getCert(
        String caName, BigInteger serialNumber) {
      return certificate;
    }

    @Override
    public void revokeCertificate(
        String caName,
        BigInteger serialNumber,
        org.xipki.pkix.cert.CrlReason reason,
        Instant invalidityTime) {
      actions.add(
          "revoke:"
              + caName
              + ":"
              + serialNumber.toString(16)
              + ":"
              + reason
              + ":"
              + invalidityTime);
    }

    @Override
    public void unsuspendCertificate(String caName, BigInteger serialNumber) {
      actions.add("unsuspend:" + caName + ":" + serialNumber.toString(16));
    }

    @Override
    public void removeCertificate(String caName, BigInteger serialNumber) {
      actions.add("remove:" + caName + ":" + serialNumber.toString(16));
    }
  }

  private static final class CertificateIssuanceClient
      extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final org.xipki.pkix.cert.X509Cert certificate;
    private final byte[] encodedCertificate;
    private final byte[] encodedKey;
    private String caName;
    private String profileName;
    private byte[] encodedCsr;
    private byte[] encodedTargetCertificate;
    private String subject;
    private Instant notBefore;
    private Instant notAfter;

    CertificateIssuanceClient(byte[] encodedCertificate) throws Exception {
      this(encodedCertificate, new byte[] {9, 8, 7});
    }

    CertificateIssuanceClient(byte[] encodedCertificate, byte[] encodedKey) throws Exception {
      this.encodedCertificate = encodedCertificate;
      this.encodedKey = encodedKey;
      certificate = org.xipki.pkix.util.X509Util.parseCert(encodedCertificate);
    }

    @Override
    public org.xipki.pkix.cert.X509Cert generateCertificate(
        String caName,
        String profileName,
        byte[] encodedCsr,
        Instant notBefore,
        Instant notAfter) {
      this.caName = caName;
      this.profileName = profileName;
      this.encodedCsr = encodedCsr;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      return certificate;
    }

    @Override
    public org.xipki.pkix.cert.KeyCertBytesPair generateKeyCert(
        String caName,
        String profileName,
        String subject,
        Instant notBefore,
        Instant notAfter) {
      this.caName = caName;
      this.profileName = profileName;
      this.subject = subject;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      return new org.xipki.pkix.cert.KeyCertBytesPair(encodedKey, encodedCertificate);
    }

    @Override
    public org.xipki.pkix.cert.X509Cert generateCrossCertificate(
        String caName,
        String profileName,
        byte[] encodedCsr,
        byte[] encodedTargetCert,
        Instant notBefore,
        Instant notAfter) {
      this.caName = caName;
      this.profileName = profileName;
      this.encodedCsr = encodedCsr;
      this.encodedTargetCertificate = encodedTargetCert;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      return certificate;
    }
  }

  private static final class CrlClient extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private static final String ENCODED_CRL =
        "MIHqMIGRAgEBMAoGCCqGSM49BAMCMC8xCzAJBgNVBAYTAkRFMQ4wDAYDVQQKDAVteW9yZzEQ"
            + "MA4GA1UEAwwHcm9vdGNhMRcNMjEwMTA4MjIzNTU0WhgPMjA3MDEyMjcyMjM1NTRaoC8wLTAK"
            + "BgNVHRQEAwIBATAfBgNVHSMEGDAWgBRD9aNDY/r27/rxEEmQmDxCnzjlADAKBggqhkjOPQQD"
            + "AgNIADBFAiEAmrFGug1AoCI/buKNJz1ZZ7wK0vrfk7j55syVjXXDBngCIDtUEuNT2+949A/L"
            + "zQsHWuCcERYYaG44X7uXS1REKAcO";

    private final List<String> actions = new ArrayList<>();
    private final byte[] encodedCrl = Base64.getDecoder().decode(ENCODED_CRL);
    private final org.xipki.pkix.cert.X509Crl crl;

    CrlClient() throws Exception {
      crl = org.xipki.pkix.util.X509Util.parseCrl(encodedCrl);
    }

    @Override
    public org.xipki.pkix.cert.X509Crl generateCrlOnDemand(String caName) {
      actions.add("generate:" + caName);
      return crl;
    }

    @Override
    public org.xipki.pkix.cert.X509Crl getCrl(String caName, long crlNumber) {
      actions.add("get:" + caName + ":" + crlNumber);
      return crl;
    }

    @Override
    public org.xipki.pkix.cert.X509Crl getCurrentCrl(String caName) {
      actions.add("current:" + caName);
      return crl;
    }
  }

  private static final class CaDetailClient extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final org.xipki.ca.api.mgmt.entry.CaEntry ca;
    private String requestedName;

    CaDetailClient() {
      var base =
          new org.xipki.ca.api.mgmt.entry.BaseCaInfo(
              "PKCS12", new org.xipki.ca.api.mgmt.Permissions(1023));
      base.setMaxValidity(org.xipki.util.conf.Validity.getInstance("365d"));
      base.setNextCrlNo(9);
      base.setCaUris(
          new org.xipki.ca.api.mgmt.CaUris(
              List.of("https://ca.example.test/ca.crt"), null, null, null));
      ca =
          new org.xipki.ca.api.mgmt.entry.CaEntry(
              base, new org.xipki.util.misc.NameId(23, "business-ca"), "password=secret");
    }

    @Override
    public org.xipki.ca.api.mgmt.entry.CaEntry getCa(String caName) {
      requestedName = caName;
      return ca;
    }
  }

  private static final class ResourceDetailClient
      extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private String requestedProfile;
    private String requestedPublisher;
    private String requestedRequestor;
    private String requestedSigner;
    private String requestedKeypairGenerator;
    private org.xipki.pkix.cert.X509Cert signerCertificate;

    @Override
    public org.xipki.ca.api.mgmt.entry.CertprofileEntry getCertprofile(String profileName) {
      requestedProfile = profileName;
      return new org.xipki.ca.api.mgmt.entry.CertprofileEntry(
          new org.xipki.util.misc.NameId(31, profileName), "xijson", "profile-conf");
    }

    @Override
    public org.xipki.ca.api.mgmt.entry.PublisherEntry getPublisher(String publisherName) {
      requestedPublisher = publisherName;
      return new org.xipki.ca.api.mgmt.entry.PublisherEntry(
          new org.xipki.util.misc.NameId(32, publisherName), "ocsp", "publisher-conf");
    }

    @Override
    public org.xipki.ca.api.mgmt.entry.RequestorEntry getRequestor(String requestorName) {
      requestedRequestor = requestorName;
      return new org.xipki.ca.api.mgmt.entry.RequestorEntry(
          new org.xipki.util.misc.NameId(33, requestorName), "cert", "requestor-conf");
    }

    @Override
    public org.xipki.ca.api.mgmt.entry.SignerEntry getSigner(String signerName) {
      requestedSigner = signerName;
      var signer =
          new org.xipki.ca.api.mgmt.entry.SignerEntry(
              signerName, "PKCS12", "signer-conf", null);
      signer.setCertificate(signerCertificate);
      return signer;
    }

    @Override
    public org.xipki.ca.api.mgmt.entry.KeypairGenEntry getKeypairGen(String name) {
      requestedKeypairGenerator = name;
      return new org.xipki.ca.api.mgmt.entry.KeypairGenEntry(
          name, "software", "keyspec=RSA/2048");
    }
  }

  private static final class ResourceMutationClient
      extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final List<String> actions = new ArrayList<>();

    @Override
    public void addCertprofile(org.xipki.ca.api.mgmt.entry.CertprofileEntry entry) {
      actions.add(
          "add-profile:"
              + entry.ident().name()
              + ":"
              + entry.type()
              + ":"
              + entry.conf());
    }

    @Override
    public void changeCertprofile(String name, String type, String conf) {
      actions.add("change-profile:" + name + ":" + type + ":" + conf);
    }

    @Override
    public void removeCertprofile(String name) {
      actions.add("remove-profile:" + name);
    }

    @Override
    public void addPublisher(org.xipki.ca.api.mgmt.entry.PublisherEntry entry) {
      actions.add(
          "add-publisher:"
              + entry.ident().name()
              + ":"
              + entry.type()
              + ":"
              + entry.conf());
    }

    @Override
    public void changePublisher(String name, String type, String conf) {
      actions.add("change-publisher:" + name + ":" + type + ":" + conf);
    }

    @Override
    public void removePublisher(String name) {
      actions.add("remove-publisher:" + name);
    }

    @Override
    public void addRequestor(org.xipki.ca.api.mgmt.entry.RequestorEntry entry) {
      actions.add(
          "add-requestor:"
              + entry.ident().name()
              + ":"
              + entry.type()
              + ":"
              + entry.conf());
    }

    @Override
    public void changeRequestor(String name, String type, String conf) {
      actions.add("change-requestor:" + name + ":" + type + ":" + conf);
    }

    @Override
    public void removeRequestor(String name) {
      actions.add("remove-requestor:" + name);
    }

    @Override
    public void addSigner(org.xipki.ca.api.mgmt.entry.SignerEntry entry) {
      actions.add(
          "add-signer:"
              + entry.name()
              + ":"
              + entry.type()
              + ":"
              + entry.conf()
              + ":"
              + entry.base64Cert());
    }

    @Override
    public void changeSigner(String name, String type, String conf, String base64Cert) {
      actions.add(
          "change-signer:" + name + ":" + type + ":" + conf + ":" + base64Cert);
    }

    @Override
    public void removeSigner(String name) {
      actions.add("remove-signer:" + name);
    }

    @Override
    public void addKeypairGen(org.xipki.ca.api.mgmt.entry.KeypairGenEntry entry) {
      actions.add(
          "add-keypair-generator:"
              + entry.name()
              + ":"
              + entry.type()
              + ":"
              + entry.conf());
    }

    @Override
    public void changeKeypairGen(String name, String type, String conf) {
      actions.add("change-keypair-generator:" + name + ":" + type + ":" + conf);
    }

    @Override
    public void removeKeypairGen(String name) {
      actions.add("remove-keypair-generator:" + name);
    }
  }

  private static final class AssociationClient extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final List<String> actions = new ArrayList<>();
    private String requestedProfileCa;
    private String requestedRequestorCa;

    @Override
    public Set<org.xipki.ca.api.mgmt.CaProfileEntry> getCertprofilesForCa(String caName) {
      requestedProfileCa = caName;
      return Set.of(
          new org.xipki.ca.api.mgmt.CaProfileEntry(
              "tls-server", List.of("web", "server")));
    }

    @Override
    public void addCertprofileToCa(String profileNameAndAliases, String caName) {
      actions.add("add-profile:" + caName + ":" + profileNameAndAliases);
    }

    @Override
    public void removeCertprofileFromCa(String profileName, String caName) {
      actions.add("remove-profile:" + caName + ":" + profileName);
    }

    @Override
    public void addPublisherToCa(String publisherName, String caName) {
      actions.add("add-publisher:" + caName + ":" + publisherName);
    }

    @Override
    public void removePublisherFromCa(String publisherName, String caName) {
      actions.add("remove-publisher:" + caName + ":" + publisherName);
    }

    @Override
    public Set<org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry> getRequestorsForCa(
        String caName) {
      requestedRequestorCa = caName;
      return Set.of(
          new org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry(
              new org.xipki.util.misc.NameId(41, "gateway-requestor"),
              new org.xipki.ca.api.mgmt.Permissions(3),
              List.of("tls-server", "code-signing")));
    }

    @Override
    public void addRequestorToCa(
        org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry requestor, String caName) {
      actions.add(
          "add-requestor:"
              + caName
              + ":"
              + requestor.requestorIdent().name()
              + ":"
              + requestor.permissions().value()
              + ":"
              + String.join(",", requestor.profiles()));
    }

    @Override
    public void removeRequestorFromCa(String requestorName, String caName) {
      actions.add("remove-requestor:" + caName + ":" + requestorName);
    }
  }

  private static final class CaMutationClient extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private static final String CA_CERTIFICATE =
        "MIIBjjCCATWgAwIBAgIBATAKBggqhkjOPQQDAjAvMQswCQYDVQQGEwJERTEOMAwGA1UECgwF"
            + "bXlvcmcxEDAOBgNVBAMMB3Jvb3RjYTEwHhcNMjEwMTA4MjE0NDU2WhcNMzEwMTA4MjE0NDU2"
            + "WjAvMQswCQYDVQQGEwJERTEOMAwGA1UECgwFbXlvcmcxEDAOBgNVBAMMB3Jvb3RjYTEwWTAT"
            + "BgcqhkjOPQIBBggqhkjOPQMBBwNCAARIy8HINvKpaTem9qTMtkCDf8580feLDNHcMHvcuGcP"
            + "I9R4sGb4GQlyrRKuvBdMQwArHJ2jNAv3nOKbcjJiBQeCo0IwQDAPBgNVHRMBAf8EBTADAQH/"
            + "MB0GA1UdDgQWBBRD9aNDY/r27/rxEEmQmDxCnzjlADAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZI"
            + "zj0EAwIDRwAwRAIgTelJ2QCH9iuUiGuLwWJBECq3LhHXljUyqfPVFBUesNcCIHKW4rd1X/E0"
            + "dhFVvNe9C/JeDba8ou8QRIAWcRsvA64Z";

    private org.xipki.ca.api.mgmt.entry.CaEntry addedCa;
    private org.xipki.ca.api.mgmt.entry.ChangeCaEntry changedCa;
    private final List<String> actions = new ArrayList<>();

    @Override
    public void addCa(org.xipki.ca.api.mgmt.entry.CaEntry entry) {
      addedCa = entry;
    }

    @Override
    public void changeCa(org.xipki.ca.api.mgmt.entry.ChangeCaEntry entry) {
      changedCa = entry;
    }

    @Override
    public void revokeCa(
        String caName, org.xipki.pkix.cert.CertRevocationInfo revocationInfo) {
      actions.add(
          "revoke:"
              + caName
              + ":"
              + revocationInfo.reason()
              + ":"
              + revocationInfo.revocationTime()
              + ":"
              + revocationInfo.invalidityTime());
    }

    @Override
    public void unrevokeCa(String caName) {
      actions.add("unrevoke:" + caName);
    }

    @Override
    public void removeCa(String caName) {
      actions.add("remove:" + caName);
    }
  }

  private static final class CaCertificateClient
      extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final List<org.xipki.pkix.cert.X509Cert> certificates;
    private String requestedCa;

    CaCertificateClient(byte[] encodedCertificate) throws Exception {
      var certificate = org.xipki.pkix.util.X509Util.parseCert(encodedCertificate);
      certificates = List.of(certificate, certificate);
    }

    @Override
    public List<org.xipki.pkix.cert.X509Cert> getCaCerts(String caName) {
      requestedCa = caName;
      return certificates;
    }
  }

  private static final class RootCaClient extends org.xipki.ca.mgmt.client.CaMgmtClient {
    private final org.xipki.pkix.cert.X509Cert certificate;
    private org.xipki.ca.api.mgmt.entry.CaEntry caEntry;
    private String profile;
    private String subject;
    private String serialNumber;
    private Instant notBefore;
    private Instant notAfter;

    RootCaClient(byte[] encodedCertificate) throws Exception {
      certificate = org.xipki.pkix.util.X509Util.parseCert(encodedCertificate);
    }

    @Override
    public org.xipki.pkix.cert.X509Cert generateRootCa(
        org.xipki.ca.api.mgmt.entry.CaEntry caEntry,
        String certprofileName,
        String subject,
        String serialNumber,
        Instant notBefore,
        Instant notAfter) {
      this.caEntry = caEntry;
      this.profile = certprofileName;
      this.subject = subject;
      this.serialNumber = serialNumber;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      return certificate;
    }
  }
}
