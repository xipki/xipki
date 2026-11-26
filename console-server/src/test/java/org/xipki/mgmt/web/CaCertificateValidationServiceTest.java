// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.ca.Crypto;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.ca.Der;
import org.xipki.mgmt.web.service.CaCertificateValidationService;
import org.xipki.mgmt.web.service.CaCertificateValidationService.ValidationPurpose;

/**
 * Real signatures and PKIX validation, ported from the original backend regression tests.
 *
 * @author palos
 */
class CaCertificateValidationServiceTest {
  private static final Instant NOW = Instant.parse("2026-10-27T00:00:00Z");

  @Test
  void validatesSignedSubCaChainAndRejectsWrongParent() throws Exception {
    var rootKey = rsa();
    var subKey = rsa();
    var root = ca(rootKey, rootKey, "CN=Root", "CN=Root", 1, -3600, 86400, 1);
    var sub = ca(subKey, rootKey, "CN=Root", "CN=Sub", 2, -60, 3600, 0);
    var service = new CaCertificateValidationService();
    var valid =
        service.validate(sub, List.of(root), Optional.of(root), NOW, ValidationPurpose.SUB_CA);
    assertTrue(valid.valid(), valid.diagnostic());
    assertEquals(List.of(sub, root), valid.chain());
    assertEquals(0, valid.pathLength());
    assertEquals("CN=Root", valid.issuer());
    var unrelatedKey = rsa();
    var unrelated = ca(unrelatedKey, unrelatedKey, "CN=Other", "CN=Other", 9, -3600, 86400, 1);
    var invalid =
        service.validate(sub, List.of(root), Optional.of(unrelated), NOW, ValidationPurpose.SUB_CA);
    assertFalse(invalid.valid());
    assertTrue(invalid.diagnostic().contains("expected parent"));
  }

  @Test
  void enforcesRootNameConstraintsAndUnknownCriticalExtensions() throws Exception {
    var key = rsa();
    var builder = builder(key, "CN=ConstrainedRoot", "CN=ConstrainedRoot", 91, -60, 86400, 1);
    builder.extension(
        "2.5.29.30",
        true,
        Der.sequence(
            Der.tagged(
                160, Der.sequence(Der.tagged(164, new X500Principal("O=Allowed").getEncoded())))));
    var root = sign(builder, key);
    var sub = ca(rsa(), key, "CN=ConstrainedRoot", "O=Forbidden,CN=Sub", 92, -60, 3600, 0);
    var validator = new CaCertificateValidationService();
    assertFalse(
        validator
            .validate(sub, List.of(root), Optional.of(root), NOW, ValidationPurpose.SUB_CA)
            .valid());
    builder.extension(
        "1.2.3.4.5.6.7", true, Der.tagged(12, "unsupported".getBytes(StandardCharsets.UTF_8)));
    var unknownCritical = sign(builder, key);
    assertFalse(
        validator
            .validate(unknownCritical, List.of(), Optional.empty(), NOW, ValidationPurpose.IMPORT)
            .valid());
  }

  @Test
  void rejectsEndEntityAndMissingKeyCertSignBeforeAcceptingCaMaterial() throws Exception {
    var key = rsa();
    var name = new X500Principal("CN=InvalidCA");
    var builder = new Builder(key, "CN=InvalidCA", "CN=InvalidCA", 71, -60, 3600);
    builder.extension("2.5.29.19", true, Der.sequence());
    builder.extension("2.5.29.15", true, Der.tagged(3, new byte[] {7, (byte) 128}));
    var validator = new CaCertificateValidationService();
    var result =
        validator.validate(
            sign(builder, key), List.of(), Optional.empty(), NOW, ValidationPurpose.IMPORT);
    assertFalse(result.valid());
    assertTrue(result.diagnostic().contains("not a CA"));
    var noSign = new Builder(key, "CN=InvalidCA", "CN=InvalidCA", 72, -60, 3600);
    noSign.extension(
        "2.5.29.19",
        true,
        Der.sequence(Der.tagged(1, new byte[] {(byte) 255}), Der.integer(BigInteger.ONE)));
    noSign.extension("2.5.29.15", true, Der.tagged(3, new byte[] {7, (byte) 128}));
    result =
        validator.validate(
            sign(noSign, key), List.of(), Optional.empty(), NOW, ValidationPurpose.IMPORT);
    assertFalse(result.valid());
    assertTrue(result.diagnostic().contains("keyCertSign"));
  }

  @Test
  void futureMaterialCanBeImportedInactiveButCannotBeActivatedAndExpiredIsRejected()
      throws Exception {
    var key = rsa();
    var validator = new CaCertificateValidationService();
    var future = ca(key, key, "CN=Future", "CN=Future", 19, 3600, 7200, 1);
    assertTrue(
        validator
            .validate(future, List.of(), Optional.empty(), NOW, ValidationPurpose.IMPORT)
            .valid());
    assertFalse(
        validator
            .validate(future, List.of(), Optional.empty(), NOW, ValidationPurpose.ACTIVATE)
            .valid());
    var expired = ca(key, key, "CN=Expired", "CN=Expired", 20, -7200, -3600, 1);
    var result =
        validator.validate(expired, List.of(), Optional.empty(), NOW, ValidationPurpose.IMPORT);
    assertFalse(result.valid());
    assertTrue(result.diagnostic().contains("expired"));
  }

  @Test
  void rejectsDuplicateUnrelatedAndExpiredIssuersAndExcessivePathLength() throws Exception {
    var rootKey = rsa();
    var otherKey = rsa();
    var root = ca(rootKey, rootKey, "CN=Root", "CN=Root", 31, -60, 86400, 1);
    var other = ca(otherKey, otherKey, "CN=Other", "CN=Other", 33, -60, 86400, 1);
    var sub = ca(rsa(), rootKey, "CN=Root", "CN=Sub", 35, -60, 3600, 0);
    var validator = new CaCertificateValidationService();
    assertFalse(
        validator
            .validate(sub, List.of(root, root), Optional.empty(), NOW, ValidationPurpose.IMPORT)
            .valid());
    assertFalse(
        validator
            .validate(sub, List.of(root, other), Optional.empty(), NOW, ValidationPurpose.IMPORT)
            .valid());
    var expiredRoot = ca(rootKey, rootKey, "CN=Root", "CN=Root", 37, -3600, -60, 1);
    assertFalse(
        validator
            .validate(sub, List.of(expiredRoot), Optional.empty(), NOW, ValidationPurpose.IMPORT)
            .valid());
    var noSubCaRoot = ca(rootKey, rootKey, "CN=Root", "CN=Root", 38, -60, 86400, 0);
    var result =
        validator.validate(
            sub, List.of(noSubCaRoot), Optional.empty(), NOW, ValidationPurpose.SUB_CA);
    assertFalse(result.valid());
    assertTrue(result.diagnostic().contains("path length"));
  }

  private static KeyPair rsa() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  private static X509Cert ca(
      KeyPair subjectKey,
      KeyPair issuerKey,
      String issuer,
      String subject,
      int serial,
      long before,
      long after,
      int pathLen)
      throws Exception {
    return sign(builder(subjectKey, issuer, subject, serial, before, after, pathLen), issuerKey);
  }

  private static Builder builder(
      KeyPair key,
      String issuer,
      String subject,
      int serial,
      long before,
      long after,
      int pathLen) {
    var builder = new Builder(key, issuer, subject, serial, before, after);
    builder.extension(
        "2.5.29.19",
        true,
        Der.sequence(
            Der.tagged(1, new byte[] {(byte) 255}), Der.integer(BigInteger.valueOf(pathLen))));
    builder.extension("2.5.29.15", true, Der.tagged(3, new byte[] {1, 6}));
    return builder;
  }

  private static X509Cert sign(Builder builder, KeyPair issuer) throws Exception {
    return Crypto.issue(
        builder.key.getPublic(),
        issuer.getPrivate(),
        builder.subject,
        builder.issuer,
        BigInteger.valueOf(builder.serial),
        NOW.plusSeconds(builder.before),
        NOW.plusSeconds(builder.after),
        builder.extensions);
  }

  private static final class Builder {
    final KeyPair key;
    final String issuer, subject;
    final int serial;
    final long before, after;
    final List<byte[]> extensions = new ArrayList<>();

    Builder(KeyPair key, String issuer, String subject, int serial, long before, long after) {
      this.key = key;
      this.issuer = issuer;
      this.subject = subject;
      this.serial = serial;
      this.before = before;
      this.after = after;
    }

    void extension(String oid, boolean critical, byte[] value) {
      extensions.add(
          Der.sequence(
              Der.oid(oid),
              Der.tagged(1, new byte[] {(byte) (critical ? 255 : 0)}),
              Der.tagged(4, value)));
    }
  }
}
