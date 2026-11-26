// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.core.Json;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Action;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Certificate;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Prepare;
import org.xipki.mgmt.web.service.CaEnrollmentRepository.Data;

/**
 * @author palos
 */
class EnrollmentJsonCompatibilityTest {
  // Captured from the original backend's new ObjectMapper().writeValueAsString(Prepare),
  // including null properties and declaration order; existing idempotency hashes depend on it.
  private static final String LEGACY =
      "{\"idempotencyKey\":\"existing-123\",\"purpose\":\"REGISTER_CA\",\"mode\":\"EXT"
          + "ERNAL\",\"name\":\"subca\",\"parentCa\":null,\"profile\":null,\"subject\":\"CN=S"
          + "ub, O=例子\",\"csr\":null,\"notBefore\":null,\"notAfter\":null,\"config\":{\"sta"
          + "tus\":\"inactive\",\"acceptUnknownRevocation\":null,\"maxValidity\":null,\"s"
          + "ignerType\":null,\"signerConf\":null,\"key\":null,\"replaceSigner\":null,\"r"
          + "eplaceCertificates\":null,\"crlControl\":null,\"ctlogControl\":null,\"revo"
          + "keSuspendedControl\":null,\"crlSignerName\":null,\"keypairGenNames\":null"
          + ",\"saveCert\":true,\"saveKeypair\":null,\"validityMode\":null,\"permissions"
          + "\":[\"enroll_cert\"],\"keepExpiredCertDays\":null,\"expirationPeriod\":null"
          + ",\"extraControl\":null,\"caUris\":null,\"encodedCert\":null,\"encodedCertch"
          + "ain\":null,\"numCrls\":null,\"serialNoLen\":16},\"key\":{\"mode\":\"pkcs11\",\"a"
          + "lgorithm\":null,\"pkcs12\":null,\"password\":null,\"keyAlias\":null,\"signat"
          + "ureAlgorithm\":null,\"module\":\"default\",\"slotIndex\":0,\"keyId\":null,\"ke"
          + "yLabel\":\"CA-key\"}}";

  @Test
  void enrollmentHashInputMatchesLegacyJacksonIncludingNullsAndOrder() {
    var p = new Prepare();
    p.idempotencyKey = "existing-123";
    p.purpose = "REGISTER_CA";
    p.mode = "EXTERNAL";
    p.name = "subca";
    p.subject = "CN=Sub, O=例子";
    p.config = new CaConfigurationRequest();
    p.config.status = "inactive";
    p.config.saveCert = true;
    p.config.permissions = List.of("enroll_cert");
    p.config.serialNoLen = 16;
    p.key = new CaKeyRequest();
    p.key.mode = "pkcs11";
    p.key.module = "default";
    p.key.slotIndex = 0;
    p.key.keyLabel = "CA-key";
    assertEquals(LEGACY, Json.write(p));
    assertArrayEquals(LEGACY.getBytes(StandardCharsets.UTF_8), Json.bytes(p));
  }

  @Test
  void readsExistingPersistedEnrollmentMetadataAndInheritedActionFields() {
    var data =
        Json.read(
            "{\"name\":\"subca\",\"mode\":\"ONLINE\",\"certificateChain\":[\"issuer\"],"
                + "\"config\":{\"status\":\"inactive\"},\"acceptUnknownRevocation\":true}",
            Data.class);
    assertEquals("subca", data.name);
    assertEquals(List.of("issuer"), data.certificateChain);
    assertEquals("inactive", data.config.status);
    assertTrue(data.acceptUnknownRevocation);
    var restored = Json.read(Json.write(data), Data.class);
    assertEquals(data.certificateChain, restored.certificateChain);
    var action = Json.read("{\"version\":7,\"certificate\":\"cert\"}", Certificate.class);
    assertEquals(7L, action.version);
    assertEquals("cert", action.certificate);
    assertThrows(
        IllegalArgumentException.class, () -> Json.read("{\"version\":\"7\"}", Action.class));
    assertThrows(
        IllegalArgumentException.class,
        () -> Json.read("{\"signerConfig\":null}", CaConfigurationRequest.class));
  }

  @Test
  void strictAssociationFieldsKeepDefaultsAndRejectCoercion() {
    var request = Json.read("{}", RequestorAssociationRequest.class);
    assertEquals(List.of("all"), request.getProfiles());
    assertEquals(List.of("all"), request.getPermissions());
    assertThrows(
        IllegalArgumentException.class,
        () -> Json.read("{\"permissions\":[1]}", RequestorAssociationRequest.class));
    assertThrows(
        IllegalArgumentException.class,
        () -> Json.read("{\"confirmNonAtomic\":1}", RequestorAssociationRequest.class));
    var profile = Json.read("{\"aliases\":[\"server\"]}", ProfileAssociationRequest.class);
    assertEquals(List.of("server"), profile.getAliases());
  }
}
