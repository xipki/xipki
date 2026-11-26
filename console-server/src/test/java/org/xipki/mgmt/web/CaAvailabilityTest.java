// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.ca.CaManagerTestProxy;
import org.xipki.mgmt.web.controller.*;
import org.xipki.mgmt.web.core.ApiException;
import org.xipki.mgmt.web.dto.KeyCertDownloadRequest;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.service.CaManagementService;

/**
 * @author palos
 */
class CaAvailabilityTest {
  @Test
  void readinessDoesNotDependOnDbSchemaManagement() throws Exception {
    var client =
        new Client() {
          @Override
          public CaSystemStatus getCaSystemStatus() {
            return CaSystemStatus.STARTED_AS_MASTER;
          }

          @Override
          public Set<String> getCaNames() {
            return Set.of();
          }

          @Override
          public Map<String, String> getDbSchemas() {
            throw new AssertionError("Readiness must not request DB schemas");
          }
        };
    assertTrue(new CaManagementService(client.manager()).isReady());
  }

  @Test
  void inactiveCaIsRejectedBeforeRemoteCertificateQuery() throws Exception {
    var client = new Client();
    var service = new CaManagementService(client.manager());
    var controller = new CertController(service, authorized(service), null);
    var error =
        assertThrows(
            ApiException.class,
            () ->
                controller.listCerts(
                    null, "inactive", null, null, null, "notBefore", 50, false, null));
    assertEquals(409, error.status());
    assertTrue(error.getMessage().contains("not running"));
    assertEquals(0, client.queries);
  }

  @Test
  void runningCaStillUsesCertificateQuery() throws Exception {
    var client = new Client();
    var service = new CaManagementService(client.manager());
    assertTrue(
        new CertController(service, authorized(service), null)
            .listCerts(null, "running", null, null, null, "notBefore", 50, false, null)
            .data
            .isEmpty());
    assertEquals(1, client.queries);
  }

  @Test
  void inactiveCaIsRejectedBeforeCrlOperations() throws Exception {
    var service = new CaManagementService(new Client().manager());
    var controller = new CrlController(service, authorized(service));
    assertEquals(
        409, assertThrows(ApiException.class, () -> controller.generateCrl("inactive")).status());
    assertEquals(
        409,
        assertThrows(ApiException.class, () -> controller.downloadCurrentCrl("inactive")).status());
    assertEquals(
        409,
        assertThrows(ApiException.class, () -> controller.downloadCrl("inactive", "1")).status());
  }

  @Test
  void missingKeypairGeneratorRejectsBothKeyGenerationRoutesBeforeRemoteIssuance()
      throws Exception {
    var client = new Client();
    var service = new CaManagementService(client.manager());
    var access =
        new AccessControl(service) {
          @Override
          public Issuance requireIssue(String permission, String ca, String profile) {
            return new Issuance(new CaIdentity(ca, "fingerprint"), profile);
          }
        };
    var controller = new CertController(service, access, null);
    var request =
        (HttpServletRequest)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {HttpServletRequest.class},
                (proxy, method, args) -> 0L);
    var response =
        (HttpServletResponse)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {HttpServletResponse.class},
                (proxy, method, args) -> null);
    var direct =
        assertThrows(
            ApiException.class,
            () ->
                controller.enrollKeyCert(
                    request, response, "child", "leaf", "CN=leaf", null, null));
    var download = new KeyCertDownloadRequest();
    download.ca = "child";
    download.profile = "leaf";
    download.subject = "CN=leaf";
    download.downloadPassword = "long-test-password";
    var packaged =
        assertThrows(ApiException.class, () -> controller.downloadKeyCert(request, download));
    assertEquals(409, direct.status());
    assertEquals(direct.getMessage(), packaged.getMessage());
    assertEquals(0, client.keyGenerations);
  }

  private static AccessControl authorized(CaManagementService service) {
    return new AccessControl(service) {
      @Override
      public CaIdentity require(String permission, String ca, String profile) {
        return new CaIdentity(ca, "fingerprint");
      }

      @Override
      public boolean allows(String permission, CaIdentity ca, String profile) {
        return true;
      }
    };
  }

  private static class Client {
    int queries;
    int keyGenerations;

    CaManager manager() {
      return CaManagerTestProxy.create(
          (method, arguments) ->
              switch (method.getName()) {
                case "getCaSystemStatus" -> getCaSystemStatus();
                case "getCaNames" -> getCaNames();
                case "getDbSchemas" -> getDbSchemas();
                case "getSuccessfulCaNames" -> getSuccessfulCaNames();
                case "getCa" -> getCa((String) arguments[0]);
                case "generateKeyCert" ->
                    generateKeyCert(
                        (String) arguments[0],
                        (String) arguments[1],
                        (String) arguments[2],
                        (Instant) arguments[3],
                        (Instant) arguments[4]);
                case "listCertificates" ->
                    listCertificates(
                        (String) arguments[0],
                        (X500Principal) arguments[1],
                        (Instant) arguments[2],
                        (Instant) arguments[3],
                        (CertListOrderBy) arguments[4],
                        (int) arguments[5]);
                default -> throw new UnsupportedOperationException(method.getName());
              });
    }

    public CaSystemStatus getCaSystemStatus() {
      return CaSystemStatus.STARTED_AS_MASTER;
    }

    public Set<String> getCaNames() {
      return Set.of("running");
    }

    public Map<String, String> getDbSchemas() {
      return Map.of();
    }

    public Set<String> getSuccessfulCaNames() {
      return Set.of("running");
    }

    public CaEntry getCa(String ca) {
      return new CaEntry(new BaseCaInfo("PKCS12", null), new NameId(null, ca), "");
    }

    public KeyCertBytesPair generateKeyCert(
        String ca, String profile, String subject, Instant from, Instant to) {
      keyGenerations++;
      throw new AssertionError("Remote key generation must not be called");
    }

    public List<CertListInfo> listCertificates(
        String ca,
        X500Principal subject,
        Instant from,
        Instant to,
        CertListOrderBy order,
        int limit)
        throws CaMgmtException {
      queries++;
      if (!ca.equals("running")) {
        throw new CaMgmtException("unknown CA " + ca);
      }
      return List.of();
    }
  }
}
