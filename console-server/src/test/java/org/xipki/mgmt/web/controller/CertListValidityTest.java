// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.servlet.http.HttpServletResponse;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.ca.CaManagerTestProxy;
import org.xipki.mgmt.web.ca.Crypto;
import org.xipki.mgmt.web.core.ApiException;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.security.AccessControl.CaIdentity;
import org.xipki.mgmt.web.security.CertificateOwnership;
import org.xipki.mgmt.web.service.CaManagementService;

/**
 * @author palos
 */
class CertListValidityTest {
  @Test
  void ownCertificatesUseTheSameValidityWindowAsXiPki() throws Exception {
    Instant from = Instant.parse("2026-10-01T12:00:00Z");
    Instant to = Instant.parse("2026-10-02T12:00:00Z");
    var client =
        new Client(
            Map.of(
                BigInteger.ONE,
                certificate(BigInteger.ONE, from.minusSeconds(2), to.plusSeconds(1)),
                BigInteger.TWO,
                certificate(BigInteger.TWO, from.plusSeconds(1), to.minusSeconds(1)),
                BigInteger.valueOf(3),
                certificate(BigInteger.valueOf(3), from.minusSeconds(1), to.plusSeconds(1)),
                BigInteger.valueOf(4),
                certificate(BigInteger.valueOf(4), from.minusSeconds(2), to)));
    var service = new CaManagementService(client.manager());
    var access =
        new AccessControl(service) {
          @Override
          public CaIdentity require(String permission, String ca, String profile) {
            return new CaIdentity(ca, "fingerprint");
          }

          @Override
          public boolean allows(String permission, CaIdentity ca, String profile) {
            return false;
          }
        };
    var ownership =
        new CertificateOwnership(null) {
          @Override
          public Page page(CaIdentity ca, String cursor) {
            return new Page(List.of("1", "2", "3", "4"), null);
          }
        };

    var result =
        new CertController(service, access, ownership)
            .listCerts(
                response(new HashMap<>()),
                "running",
                null,
                from.toString(),
                to.toString(),
                "notBefore",
                50,
                true,
                null);

    assertEquals(List.of("1"), result.data.stream().map(cert -> cert.getSerialNumber()).toList());
  }

  @Test
  void ownCertificateSubjectSearchAcceptsXiPkiWildcard() throws Exception {
    var client =
        new Client(
            Map.of(
                BigInteger.ONE,
                certificate(
                    BigInteger.ONE,
                    Instant.parse("2026-01-01T00:00:00Z"),
                    Instant.parse("2027-01-01T00:00:00Z"),
                    "CN=Alice")));
    var service = new CaManagementService(client.manager());
    var access =
        new AccessControl(service) {
          @Override
          public CaIdentity require(String permission, String ca, String profile) {
            return new CaIdentity(ca, "fingerprint");
          }

          @Override
          public boolean allows(String permission, CaIdentity ca, String profile) {
            return false;
          }
        };
    var ownership =
        new CertificateOwnership(null) {
          @Override
          public Page page(CaIdentity ca, String cursor) {
            return new Page(List.of("1"), null);
          }
        };

    var result =
        new CertController(service, access, ownership)
            .listCerts(
                response(new HashMap<>()),
                "running",
                "CN=Al*",
                null,
                null,
                "notBefore",
                50,
                true,
                null);

    assertEquals(List.of("1"), result.data.stream().map(cert -> cert.getSerialNumber()).toList());
  }

  @Test
  void ownCertificateSubjectSearchAllowsOtherRdnsBetweenRequestedRdns() throws Exception {
    var client =
        new Client(
            Map.of(
                BigInteger.ONE,
                certificate(
                    BigInteger.ONE,
                    Instant.parse("2026-01-01T00:00:00Z"),
                    Instant.parse("2027-01-01T00:00:00Z"),
                    "CN=Alice,OU=Engineering,O=Example")));
    var service = new CaManagementService(client.manager());
    var access =
        new AccessControl(service) {
          @Override
          public CaIdentity require(String permission, String ca, String profile) {
            return new CaIdentity(ca, "fingerprint");
          }

          @Override
          public boolean allows(String permission, CaIdentity ca, String profile) {
            return false;
          }
        };
    var ownership =
        new CertificateOwnership(null) {
          @Override
          public Page page(CaIdentity ca, String cursor) {
            return new Page(List.of("1"), null);
          }
        };

    var result =
        new CertController(service, access, ownership)
            .listCerts(
                response(new HashMap<>()),
                "running",
                "CN=Alice,O=Example",
                null,
                null,
                "notBefore",
                50,
                true,
                null);

    assertEquals(List.of("1"), result.data.stream().map(cert -> cert.getSerialNumber()).toList());
  }

  @Test
  void legacyCertificateQueryReturnsAllOwnedMatchesWithinItsExistingCap() throws Exception {
    var from = Instant.parse("2026-01-01T00:00:00Z");
    var to = Instant.parse("2027-01-01T00:00:00Z");
    var client =
        new Client(
            Map.of(
                BigInteger.ONE,
                certificate(BigInteger.ONE, from, to),
                BigInteger.TWO,
                certificate(BigInteger.TWO, from, to)));
    var service = new CaManagementService(client.manager());
    var access =
        new AccessControl(service) {
          @Override
          public CaIdentity require(String permission, String ca, String profile) {
            return new CaIdentity(ca, "fingerprint");
          }

          @Override
          public boolean allows(String permission, CaIdentity ca, String profile) {
            return false;
          }
        };
    var ownership =
        new CertificateOwnership(null) {
          @Override
          public List<String> serials(CaIdentity ca, int limit) {
            return List.of("1", "2");
          }

          @Override
          public Page page(CaIdentity ca, String cursor) {
            return new Page(List.of("1"), "second-page");
          }
        };

    var headers = new HashMap<String, String>();
    var result =
        new CertController(service, access, ownership)
            .listCerts(
                response(headers), "running", null, null, null, "notBefore", 50, false, null);

    assertEquals(
        List.of("1", "2"), result.data.stream().map(cert -> cert.getSerialNumber()).toList());
    assertEquals(null, headers.get("X-Next-Cursor"));
  }

  @Test
  void legacyCertificateQueryRejectsHistoriesBeyondItsCapBeforeRemoteReads() throws Exception {
    var client = new Client(Map.of());
    var service = new CaManagementService(client.manager());
    var access =
        new AccessControl(service) {
          @Override
          public CaIdentity require(String permission, String ca, String profile) {
            return new CaIdentity(ca, "fingerprint");
          }

          @Override
          public boolean allows(String permission, CaIdentity ca, String profile) {
            return false;
          }
        };
    var ownership =
        new CertificateOwnership(null) {
          @Override
          public List<String> serials(CaIdentity ca, int limit) {
            return IntStream.rangeClosed(1, 1001).mapToObj(Integer::toHexString).toList();
          }
        };

    var error =
        assertThrows(
            ApiException.class,
            () ->
                new CertController(service, access, ownership)
                    .listCerts(
                        response(new HashMap<>()),
                        "running",
                        null,
                        null,
                        null,
                        "notBefore",
                        50,
                        false,
                        null));

    assertEquals(409, error.status());
    assertEquals(0, client.certReads);
  }

  @Test
  void ownCertificateSearchCanReachPastTheFirstThousandOwnershipRecords() throws Exception {
    var serial = BigInteger.valueOf(1001);
    var client =
        new Client(
            Map.of(
                serial,
                certificate(
                    serial,
                    Instant.parse("2026-01-01T00:00:00Z"),
                    Instant.parse("2027-01-01T00:00:00Z"))));
    var service = new CaManagementService(client.manager());
    var access =
        new AccessControl(service) {
          @Override
          public CaIdentity require(String permission, String ca, String profile) {
            return new CaIdentity(ca, "fingerprint");
          }

          @Override
          public boolean allows(String permission, CaIdentity ca, String profile) {
            return false;
          }
        };
    var ownership =
        new CertificateOwnership(null) {
          @Override
          public Page page(CaIdentity ca, String cursor) {
            int start = cursor == null ? 1 : Integer.parseInt(cursor) + 1;
            int end = Math.min(start + 49, 1001);
            var serials = IntStream.rangeClosed(start, end).mapToObj(Integer::toHexString).toList();
            return new Page(serials, end < 1001 ? Integer.toString(end) : null);
          }
        };
    var controller = new CertController(service, access, ownership);
    var found = new ArrayList<String>();
    String cursor = null;
    int pages = 0;
    do {
      var headers = new HashMap<String, String>();
      var result =
          controller.listCerts(
              response(headers), "running", null, null, null, "notBefore", 1, true, cursor);
      found.addAll(result.data.stream().map(cert -> cert.getSerialNumber()).toList());
      cursor = headers.get("X-Next-Cursor");
      pages++;
    } while (cursor != null);

    assertEquals(21, pages);
    assertEquals(List.of(serial.toString(16)), found);
  }

  private static HttpServletResponse response(Map<String, String> headers) {
    return (HttpServletResponse)
        Proxy.newProxyInstance(
            CertListValidityTest.class.getClassLoader(),
            new Class<?>[] {HttpServletResponse.class},
            (proxy, method, args) -> {
              if (method.getName().equals("setHeader")) {
                headers.put((String) args[0], (String) args[1]);
              }
              return null;
            });
  }

  private static CertWithRevocationInfo certificate(BigInteger serial, Instant from, Instant to)
      throws Exception {
    return certificate(serial, from, to, "CN=Test");
  }

  private static CertWithRevocationInfo certificate(
      BigInteger serial, Instant from, Instant to, String subject) throws Exception {
    var keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var cert =
        Crypto.issue(
            keys.getPublic(), keys.getPrivate(), subject, subject, serial, from, to, List.of());
    return new CertWithRevocationInfo(new CertWithDbId(cert), "test", null);
  }

  private static class Client {
    private final Map<BigInteger, CertWithRevocationInfo> certs;
    int certReads;

    Client(Map<BigInteger, CertWithRevocationInfo> certs) {
      this.certs = certs;
    }

    CaManager manager() {
      return CaManagerTestProxy.create(
          (method, arguments) ->
              switch (method.getName()) {
                case "getSuccessfulCaNames" -> getSuccessfulCaNames();
                case "getCert" -> getCert((String) arguments[0], (BigInteger) arguments[1]);
                default -> throw new UnsupportedOperationException(method.getName());
              });
    }

    public Set<String> getSuccessfulCaNames() {
      return Set.of("running");
    }

    public CertWithRevocationInfo getCert(String ca, BigInteger serial) {
      certReads++;
      return certs.get(serial);
    }
  }
}
